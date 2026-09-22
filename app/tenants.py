"""租户注册、合作方凭证（API Key）与签名密钥管理。

凭证隔离原则：
* key_id 全局唯一，校验时必须带出租户，绝不以“猜中的租户”继续处理；
* 明文 secret 仅在签发时返回一次，存储只留 SHA-256 哈希；
* 缺失 / 不存在 / secret 错误 / 已吊销 / 已过期 / 作用域不足分别抛出不同错误码。
"""
from __future__ import annotations

import secrets as _secrets
import time
from types import SimpleNamespace

from .crypto import hash_credential
from .errors import (
    CredentialBadSecretError,
    ValidationError,
    CredentialExpiredError,
    CredentialMissingError,
    CredentialRevokedError,
    CredentialUnknownError,
    GatewayError,
    ScopeInsufficientError,
)


class TenantExistsError(GatewayError):
    code = "tenant_exists"
    status_code = 409


class TenantNotFoundError(GatewayError):
    code = "tenant_not_found"
    status_code = 404


def _new_key_id() -> str:
    return "kid-" + _secrets.token_hex(8)


def _new_api_key_secret() -> str:
    return "sk-" + _secrets.token_urlsafe(24)


class TenantRegistry:
    def __init__(self, store, audit=None, *, clock=time.time) -> None:
        self._tenants = store.collection("tenants")
        self._apikeys = store.collection("apikeys")
        self._sigkeys = store.collection("signingkeys")  # key: tenant_id -> list
        self._audit = audit
        self._clock = clock

    # ---- 租户与签名密钥 --------------------------------------------------

    def register_tenant(self, tenant_id: str, name: str) -> dict:
        if not tenant_id:
            raise ValidationError("tenant_id 不能为空", tenant_id=tenant_id)

        def _reg(data: dict) -> None:
            if tenant_id in data:
                raise TenantExistsError(f"租户 {tenant_id!r} 已存在", tenant_id=tenant_id)
            data[tenant_id] = {
                "tenant_id": tenant_id,
                "name": name,
                "created_at": self._clock(),
            }

        self._tenants.modify(_reg)
        # 初始化空签名密钥列表，避免后续读取 KeyError
        self._sigkeys.update_atomic(tenant_id, lambda v: v if v is not None else [], factory=list)
        return self._tenants.get(tenant_id)

    def _require_tenant(self, tenant_id: str) -> dict:
        tenant = self._tenants.get(tenant_id)
        if tenant is None:
            raise TenantNotFoundError(f"租户 {tenant_id!r} 不存在", tenant_id=tenant_id)
        return tenant

    def rotate_signing_key(self, tenant_id: str, *, retire_old: bool = False) -> dict:
        """签发新签名密钥。

        retire_old=False 时新旧密钥并存（均 active），轮换期旧令牌不被误拒；
        retire_old=True 时该租户既有密钥全部置 retired，旧签名令牌将得到
        token_key_retired 而非 token_key_unknown。
        """
        self._require_tenant(tenant_id)
        kid = _new_key_id()
        record = {
            "kid": kid,
            "tenant_id": tenant_id,
            "secret": _secrets.token_urlsafe(32),
            "status": "active",
            "created_at": self._clock(),
        }

        def _rotate(keys):
            if keys is None:
                keys = []
            if retire_old:
                for k in keys:
                    if k["status"] == "active":
                        k["status"] = "retired"
                        k["retired_at"] = self._clock()
            keys.append(record)
            return keys

        self._sigkeys.update_atomic(tenant_id, _rotate, factory=list)
        if self._audit is not None:
            self._audit.record(
                "signing_key_rotate",
                tenant_id=tenant_id,
                result="state_change",
                detail={"kid": kid, "retire_old": retire_old},
            )
        return record

    def get_signing_keys(self, tenant_id: str) -> dict[str, SimpleNamespace]:
        """返回该租户全部密钥（含 retired，用于区分“退役”与“未知 kid”）。"""
        keys = self._sigkeys.get(tenant_id, [])
        return {
            k["kid"]: SimpleNamespace(secret=k["secret"], status=k["status"], kid=k["kid"])
            for k in keys
        }

    # ---- 合作方 API Key --------------------------------------------------

    def issue_api_key(
        self,
        tenant_id: str,
        scopes: list[str],
        ttl_seconds: float | None = None,
    ) -> dict:
        self._require_tenant(tenant_id)
        key_id = _new_key_id()
        secret = _new_api_key_secret()
        now = self._clock()
        record = {
            "key_id": key_id,
            "tenant_id": tenant_id,
            "secret_hash": hash_credential(secret),
            "scopes": list(scopes),
            "status": "active",
            "issued_at": now,
            "expires_at": None if ttl_seconds is None else now + ttl_seconds,
        }
        self._apikeys.put(key_id, record)
        if self._audit is not None:
            self._audit.record(
                "api_key_issue",
                tenant_id=tenant_id,
                result="state_change",
                detail={"key_id": key_id, "scopes": list(scopes), "secret": secret},
            )
        # 明文仅此一次返回
        return {"key_id": key_id, "secret": secret, "record": record}

    def revoke_api_key(self, tenant_id: str, key_id: str) -> None:
        self._require_tenant(tenant_id)

        def _revoke(data: dict) -> None:
            rec = data.get(key_id)
            if rec is None or rec["tenant_id"] != tenant_id:
                raise CredentialUnknownError(f"凭证 {key_id!r} 不属于租户 {tenant_id!r}", tenant_id=tenant_id)
            rec["status"] = "revoked"
            rec["revoked_at"] = self._clock()

        self._apikeys.modify(_revoke)
        if self._audit is not None:
            self._audit.record(
                "api_key_revoke",
                tenant_id=tenant_id,
                result="state_change",
                detail={"key_id": key_id},
            )

    def authenticate(
        self,
        tenant_id: str | None,
        key_id: str | None,
        secret: str | None,
        required_scope: str,
    ) -> dict:
        """校验合作方凭证并确认作用域，失败原因逐一可区分。"""

        def _deny(code: str, message: str) -> None:
            if self._audit is not None:
                self._audit.record(
                    "api_key_auth",
                    tenant_id=tenant_id or "-",
                    result="denied",
                    detail={
                        "reason": code,
                        "key_id": key_id,
                        "required_scope": required_scope,
                        "secret": secret or "",
                    },
                )
            err_map = {
                "credential_missing": CredentialMissingError,
                "credential_unknown": CredentialUnknownError,
                "credential_bad_secret": CredentialBadSecretError,
                "credential_revoked": CredentialRevokedError,
                "credential_expired": CredentialExpiredError,
                "scope_insufficient": ScopeInsufficientError,
            }
            raise err_map[code](message, tenant_id=tenant_id)

        if not tenant_id or not key_id or not secret:
            _deny("credential_missing", "租户/Key ID/Secret 均不能为空")
        # 租户必须存在；不存在直接按未知凭证拒绝，绝不退化处理
        if self._tenants.get(tenant_id) is None:
            _deny("credential_unknown", f"租户 {tenant_id!r} 不存在")

        record = self._apikeys.get(key_id)
        if record is None or record["tenant_id"] != tenant_id:
            _deny("credential_unknown", f"凭证 {key_id!r} 对租户 {tenant_id!r} 无效")
        if record["secret_hash"] != hash_credential(secret):
            _deny("credential_bad_secret", "凭证 Secret 不匹配")
        if record["status"] == "revoked":
            _deny("credential_revoked", f"凭证 {key_id!r} 已吊销")
        exp = record.get("expires_at")
        if exp is not None and exp <= self._clock():
            _deny("credential_expired", f"凭证 {key_id!r} 已过期")
        if required_scope not in record["scopes"]:
            _deny("scope_insufficient", f"缺少作用域 {required_scope!r}")

        if self._audit is not None:
            self._audit.record(
                "api_key_auth",
                tenant_id=tenant_id,
                result="allowed",
                detail={"key_id": key_id, "required_scope": required_scope, "secret": secret},
            )
        return {"tenant_id": tenant_id, "key_id": key_id, "scopes": list(record["scopes"])}
