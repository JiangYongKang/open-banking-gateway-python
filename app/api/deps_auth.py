"""HTTP 鉴权辅助：解析 Bearer 令牌并完成作用域/租户校验、限流。"""
from __future__ import annotations

from fastapi import Request

from app.errors import ErrorCode, GatewayError
from app.models import TokenClaims


def bearer_token(authorization: str) -> str:
    if not authorization:
        raise GatewayError(ErrorCode.MISSING_TOKEN, "缺少 Authorization 头")
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise GatewayError(ErrorCode.MALFORMED_TOKEN,
                           "Authorization 头应为 'Bearer <token>'")
    return parts[1].strip()


def endpoint_name(request: Request) -> str:
    return f"{request.method} {request.url.path}"


def authorize(request: Request, authorization: str, required_scopes: list[str],
              *, required_tenant: str | None = None) -> TokenClaims:
    """令牌校验 + 限流 + 作用域/租户校验的标准入口。

    顺序：先鉴权（拿到可信 tenant），再按租户/接口限流；
    鉴权失败不消耗额度。
    """
    state = request.app.state.obg
    token = bearer_token(authorization)
    claims = state.auth.verify_access_token(
        token, required_scopes=required_scopes, required_tenant=required_tenant)
    state.ratelimit.acquire(claims.tenant_id, endpoint_name(request))
    return claims
