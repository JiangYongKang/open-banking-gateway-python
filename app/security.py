"""入口安全依赖。

* :func:`api_key_auth`：从 ``X-Tenant-Id`` / ``X-API-Key`` 头校验合作方凭证；
  解析为 "key_id:secret"。缺失、过期、吊销、作用域不足全部给出不同错误码，
  且绝不以其它租户身份继续处理。
* :func:`bearer_auth`：校验 Authorization: Bearer 令牌。算法白名单优先，
  kid 仅在当前租户密钥集合内查找（轮换期新旧并存不被误拒，退役/未知/签名错/
  过期/算法不允许分别可区分）。
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Header

from .errors import CredentialMissingError, TokenMalformedError
from .tokens import verify_token


@dataclass
class Principal:
    tenant_id: str
    kind: str  # "api_key" | "access_token"
    key_id: str | None = None
    scopes: list[str] | None = None


def build_security_deps(registry, settings, *, clock=None):
    """构造绑定了 registry 与 settings 的 FastAPI 依赖可调用对象。"""

    verify_kwargs = {"allowed_algorithms": settings.allowed_algorithms}
    if clock is not None:
        verify_kwargs["now"] = clock()

    def api_key_auth(
        required_scope: str,
        x_tenant_id: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
    ) -> Principal:
        key_id, secret = (None, None)
        if x_api_key:
            if ":" not in x_api_key:
                # 形态错误与“缺失”区分：这里按 malformed 拒绝
                raise CredentialMissingError(
                    "X-API-Key 必须形如 'key_id:secret'", tenant_id=x_tenant_id
                )
            key_id, _, secret = x_api_key.partition(":")
        record = registry.authenticate(x_tenant_id, key_id, secret, required_scope)
        return Principal(
            tenant_id=record["tenant_id"], kind="api_key",
            key_id=record["key_id"], scopes=record["scopes"],
        )

    def bearer_auth(
        required_scope: str,
        x_tenant_id: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> Principal:
        if not x_tenant_id:
            raise CredentialMissingError("缺少 X-Tenant-Id 头")
        if not authorization or not authorization.startswith("Bearer "):
            raise CredentialMissingError("缺少 Bearer 访问令牌")
        token = authorization[len("Bearer "):].strip()
        if not token:
            raise TokenMalformedError("Bearer 令牌为空")
        # 仅传入当前租户的密钥集合：kid 不跨租户匹配
        keys = registry.get_signing_keys(x_tenant_id)
        if clock is not None:
            verify_kwargs["now"] = clock()
        claims = verify_token(token, keys, **verify_kwargs)
        scopes = claims.get("scope", [])
        if required_scope not in scopes:
            from .errors import ScopeInsufficientError

            if registry._audit is not None:  # 记录越权/作用域拒绝
                registry._audit.record(
                    "token_scope_check",
                    tenant_id=x_tenant_id,
                    result="denied",
                    detail={"reason": "scope_insufficient", "kid": claims.get("kid"),
                            "required_scope": required_scope, "token": token},
                )
            raise ScopeInsufficientError(
                f"令牌缺少作用域 {required_scope!r}", tenant_id=x_tenant_id
            )
        if claims.get("iss") != x_tenant_id:
            # 令牌主体与入口租户不一致即拒绝（防止 A 租户令牌在 B 入口使用）
            from .errors import CredentialUnknownError

            raise CredentialUnknownError(
                "令牌签发租户与请求租户不一致", tenant_id=x_tenant_id
            )
        return Principal(
            tenant_id=x_tenant_id, kind="access_token",
            key_id=claims.get("kid"), scopes=list(scopes),
        )

    return api_key_auth, bearer_auth
