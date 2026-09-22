"""合作方凭证校验与令牌签发/校验。

判定顺序固定，错误码互斥：
凭证: 缺失 -> 未知租户 -> 密钥错误 -> 已吊销 -> 已过期
令牌: 缺失 -> 结构错误 -> 算法不在白名单 -> 密钥未知/退役 -> 签名错误
      -> 令牌过期 -> 凭证已吊销/过期 -> 租户不匹配 -> 作用域不足
"""
from __future__ import annotations

import json
import uuid
from typing import NoReturn

from app.crypto import (
    b64url_decode,
    b64url_encode,
    constant_time_equals,
    inspect_token,
    issue_token,
    sign,
)
from app.errors import ErrorCode, GatewayError
from app.logging_utils import get_logger
from app.models import PartnerCredential, TokenClaims

logger = get_logger("auth")


class AuthService:
    def __init__(self, storage, audit, key_service, settings, clock) -> None:  # noqa: ANN001
        self.storage = storage
        self.audit = audit
        self.keys = key_service
        self.settings = settings
        self.clock = clock

    # ---- 合作方凭证管理 ------------------------------------------------
    def register_credential(self, credential_id: str, tenant_id: str, secret: str,
                            scopes: list[str], ttl_seconds: int = 0) -> PartnerCredential:
        if not credential_id or not tenant_id or not secret:
            raise GatewayError(ErrorCode.MISSING_CREDENTIALS,
                               "credential_id/tenant_id/secret 均不能为空")
        with self.storage.lock:
            if credential_id in self.storage.credentials:
                raise GatewayError(ErrorCode.INTERNAL_ERROR,
                                   f"凭证已存在: {credential_id}", status_code=409)
            cred = PartnerCredential(
                credential_id=credential_id, tenant_id=tenant_id, secret=secret,
                scopes=list(scopes), revoked=False,
                expires_at=0.0 if ttl_seconds <= 0 else self.clock.now() + ttl_seconds,
            )
            self.storage.credentials[credential_id] = cred
        self.audit.write(tenant_id, "credential_register", "state_change",
                         f"登记合作方凭证 {credential_id}",
                         {"credential_id": credential_id, "secret": secret,
                          "scopes": list(scopes)})
        logger.info("credential registered id=%s tenant=%s scopes=%s",
                    credential_id, tenant_id, scopes)
        return cred

    def revoke_credential(self, credential_id: str) -> None:
        with self.storage.lock:
            cred = self.storage.credentials.get(credential_id)
            if cred is None:
                raise GatewayError(ErrorCode.UNKNOWN_TENANT,
                                   f"未知凭证: {credential_id}", status_code=404)
            if cred.revoked:
                return
            cred.revoked = True
            tenant = cred.tenant_id
        self.audit.write(tenant, "credential_revoke", "state_change",
                         f"凭证吊销 {credential_id}", {"credential_id": credential_id})
        logger.info("credential revoked id=%s", credential_id)

    # ---- 凭证校验 ------------------------------------------------------
    def authenticate_partner(self, credential_id: str, secret: str) -> PartnerCredential:
        if not credential_id or not secret:
            self._deny("-", "partner_auth", ErrorCode.MISSING_CREDENTIALS,
                       "缺少凭证标识或密钥",
                       {"credential_id": credential_id or "[none]", "secret": secret})
        with self.storage.lock:
            cred = self.storage.credentials.get(credential_id)
            if cred is None:
                self._deny("-", "partner_auth", ErrorCode.UNKNOWN_TENANT,
                           f"未知合作方凭证: {credential_id}",
                           {"credential_id": credential_id, "secret": secret})
            assert cred is not None
            if not constant_time_equals(cred.secret.encode(), secret.encode()):
                self._deny(cred.tenant_id, "partner_auth",
                           ErrorCode.INVALID_CREDENTIAL_SECRET, "凭证密钥不匹配",
                           {"credential_id": credential_id, "secret": secret})
            if cred.revoked:
                self._deny(cred.tenant_id, "partner_auth", ErrorCode.CREDENTIAL_REVOKED,
                           "凭证已被吊销", {"credential_id": credential_id})
            if cred.expires_at and cred.expires_at <= self.clock.now():
                self._deny(cred.tenant_id, "partner_auth", ErrorCode.CREDENTIAL_EXPIRED,
                           "凭证已过期",
                           {"credential_id": credential_id,
                            "expires_at": cred.expires_at})
            return cred

    # ---- 令牌签发 ------------------------------------------------------
    def issue_access_token(self, credential_id: str,
                           secret: str) -> tuple[str, TokenClaims]:
        cred = self.authenticate_partner(credential_id, secret)
        key = self.keys.get_active_signing_key()
        now = self.clock.now()
        claims = TokenClaims(
            jti=uuid.uuid4().hex, tenant_id=cred.tenant_id,
            credential_id=cred.credential_id, scopes=list(cred.scopes),
            kid=key.kid, alg=key.alg, iat=now, exp=now + self.settings.token_ttl_seconds,
        )
        token = issue_token(key.secret, key.alg, key.kid, claims)
        self.audit.write(cred.tenant_id, "token_issue", "allowed",
                         f"签发访问令牌 jti={claims.jti} kid={key.kid}",
                         {"credential_id": credential_id, "token": token,
                          "scopes": claims.scopes, "kid": key.kid})
        logger.info("token issued tenant=%s jti=%s kid=%s", cred.tenant_id,
                    claims.jti, key.kid)
        return token, claims

    # ---- 令牌校验 ------------------------------------------------------
    def verify_access_token(self, token: str, *, required_scopes: list[str],
                            required_tenant: str | None = None) -> TokenClaims:
        if not token:
            self._deny(required_tenant or "-", "token_verify",
                       ErrorCode.MISSING_TOKEN, "缺少 Authorization Bearer 令牌",
                       {"token": token})
        try:
            info = inspect_token(token)  # 结构错误 -> MALFORMED_TOKEN
        except GatewayError as exc:
            self._deny(required_tenant or "-", "token_verify", exc.code, exc.message,
                       {"token": token})
        header, payload = info["header"], info["payload"]
        alg = header.get("alg")
        kid = header.get("kid")

        if alg not in self.settings.allowed_algs:
            self._deny(payload.get("tenant_id", "-"), "token_verify",
                       ErrorCode.TOKEN_ALG_NOT_ALLOWED,
                       f"签名算法不在白名单: {alg}",
                       {"token": token, "alg": alg,
                        "allowed": list(self.settings.allowed_algs)})

        # 取钥即区分 未知 / 退役
        try:
            key = self.keys.resolve_for_verify(kid)
        except GatewayError as exc:
            self._deny(payload.get("tenant_id", "-"), "token_verify", exc.code,
                       exc.message, {"token": token, "kid": kid})
        if alg != key.alg:
            self._deny(payload.get("tenant_id", "-"), "token_verify",
                       ErrorCode.TOKEN_ALG_NOT_ALLOWED,
                       f"令牌算法 {alg} 与密钥算法 {key.alg} 不一致",
                       {"token": token, "kid": kid})

        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        expected = sign(key.secret, signing_input, alg)
        if not constant_time_equals(expected, b64url_decode(parts[2])):
            self._deny(payload.get("tenant_id", "-"), "token_verify",
                       ErrorCode.TOKEN_BAD_SIGNATURE, "令牌签名校验失败",
                       {"token": token, "kid": kid})

        try:
            claims = TokenClaims(
                jti=payload["jti"], tenant_id=payload["tenant_id"],
                credential_id=payload["credential_id"], scopes=list(payload["scopes"]),
                kid=kid, alg=alg, iat=float(payload["iat"]), exp=float(payload["exp"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            self._deny("-", "token_verify", ErrorCode.MALFORMED_TOKEN,
                       f"令牌声明不完整: {exc}", {"token": token})

        if claims.exp <= self.clock.now():
            self._deny(claims.tenant_id, "token_verify", ErrorCode.TOKEN_EXPIRED,
                       "访问令牌已过期", {"jti": claims.jti, "exp": claims.exp})

        # 令牌仍然有效但其所属凭证已被吊销/过期：拒绝，不得继续放行
        with self.storage.lock:
            cred = self.storage.credentials.get(claims.credential_id)
            if cred is None or cred.tenant_id != claims.tenant_id:
                self._deny(claims.tenant_id, "token_verify",
                           ErrorCode.UNKNOWN_TENANT, "令牌对应凭证不存在或租户不匹配",
                           {"credential_id": claims.credential_id})
            assert cred is not None
            if cred.revoked:
                self._deny(claims.tenant_id, "token_verify",
                           ErrorCode.CREDENTIAL_REVOKED, "令牌所属凭证已被吊销",
                           {"credential_id": cred.credential_id})
            if cred.expires_at and cred.expires_at <= self.clock.now():
                self._deny(claims.tenant_id, "token_verify",
                           ErrorCode.CREDENTIAL_EXPIRED, "令牌所属凭证已过期",
                           {"credential_id": cred.credential_id})

        if required_tenant is not None and claims.tenant_id != required_tenant:
            self._deny(claims.tenant_id, "token_verify", ErrorCode.TENANT_MISMATCH,
                       f"租户隔离拒绝: 令牌属于 {claims.tenant_id}，"
                       f"资源属于 {required_tenant}",
                       {"token_tenant": claims.tenant_id,
                        "required_tenant": required_tenant})

        missing = [s for s in required_scopes if s not in claims.scopes]
        if missing:
            self._deny(claims.tenant_id, "token_verify", ErrorCode.SCOPE_INSUFFICIENT,
                       f"作用域不足，缺少: {','.join(missing)}",
                       {"required": list(required_scopes), "granted": claims.scopes,
                        "missing": missing})

        logger.info("token verified tenant=%s jti=%s scopes=%s",
                    claims.tenant_id, claims.jti, claims.scopes)
        return claims

    def _deny(self, tenant: str, action: str, code: ErrorCode, message: str,
              context: dict) -> NoReturn:
        self.audit.write(tenant, action, "denied", f"{code.value}: {message}", context)
        logger.warning("auth deny action=%s code=%s detail=%s input=%s",
                       action, code.value, message,
                       json.dumps({k: ("<redacted>" if k in ("secret", "token") else v)
                                   for k, v in context.items()}, ensure_ascii=False))
        raise GatewayError(code, message)
