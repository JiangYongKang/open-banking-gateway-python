"""统一错误码与异常处理。

不同失败原因必须可区分，因此每个错误码唯一映射到一种判定结果，
响应体形如 {"error": {"code": ..., "message": ..., "details": {...}}}。
"""
from __future__ import annotations

from enum import Enum

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


class ErrorCode(str, Enum):
    # 合作方凭证
    MISSING_CREDENTIALS = "missing_credentials"
    UNKNOWN_TENANT = "unknown_tenant"
    INVALID_CREDENTIAL_SECRET = "invalid_credential_secret"
    CREDENTIAL_REVOKED = "credential_revoked"
    CREDENTIAL_EXPIRED = "credential_expired"
    SCOPE_INSUFFICIENT = "scope_insufficient"
    TENANT_MISMATCH = "tenant_mismatch"
    # 访问令牌
    MISSING_TOKEN = "missing_token"
    MALFORMED_TOKEN = "malformed_token"
    TOKEN_ALG_NOT_ALLOWED = "token_alg_not_allowed"
    TOKEN_BAD_SIGNATURE = "token_bad_signature"
    TOKEN_KEY_RETIRED = "token_key_retired"
    TOKEN_KEY_UNKNOWN = "token_key_unknown"
    TOKEN_EXPIRED = "token_expired"
    # 同意
    CONSENT_NOT_FOUND = "consent_not_found"
    CONSENT_INVALID_TRANSITION = "consent_invalid_transition"
    CONSENT_REVOKED = "consent_revoked"
    CONSENT_EXPIRED = "consent_expired"
    CONSENT_SCOPE_INSUFFICIENT = "consent_scope_insufficient"
    CONSENT_RESOURCE_FORBIDDEN = "consent_resource_forbidden"
    # 限流/配额/规模
    RATE_LIMITED_REJECT = "rate_limited_reject"
    RATE_LIMITED_TIMEOUT = "rate_limited_timeout"
    QUOTA_EXHAUSTED = "quota_exhausted"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    REQUEST_TIMEOUT = "request_timeout"
    # 回调
    CALLBACK_EVENT_DEAD = "callback_event_dead"
    # 通用
    INTERNAL_ERROR = "internal_error"


# 错误码默认 HTTP 状态
_DEFAULT_STATUS = {
    ErrorCode.MISSING_CREDENTIALS: 401,
    ErrorCode.MISSING_TOKEN: 401,
    ErrorCode.MALFORMED_TOKEN: 401,
    ErrorCode.TOKEN_EXPIRED: 401,
    ErrorCode.UNKNOWN_TENANT: 401,
    ErrorCode.INVALID_CREDENTIAL_SECRET: 401,
    ErrorCode.CREDENTIAL_REVOKED: 401,
    ErrorCode.CREDENTIAL_EXPIRED: 401,
    ErrorCode.TOKEN_BAD_SIGNATURE: 401,
    ErrorCode.TOKEN_ALG_NOT_ALLOWED: 401,
    ErrorCode.TOKEN_KEY_RETIRED: 401,
    ErrorCode.TOKEN_KEY_UNKNOWN: 401,
    ErrorCode.SCOPE_INSUFFICIENT: 403,
    ErrorCode.TENANT_MISMATCH: 403,
    ErrorCode.CONSENT_REVOKED: 403,
    ErrorCode.CONSENT_EXPIRED: 403,
    ErrorCode.CONSENT_SCOPE_INSUFFICIENT: 403,
    ErrorCode.CONSENT_RESOURCE_FORBIDDEN: 403,
    ErrorCode.CONSENT_NOT_FOUND: 404,
    ErrorCode.CONSENT_INVALID_TRANSITION: 409,
    ErrorCode.RATE_LIMITED_REJECT: 429,
    ErrorCode.RATE_LIMITED_TIMEOUT: 429,
    ErrorCode.QUOTA_EXHAUSTED: 429,
    ErrorCode.PAYLOAD_TOO_LARGE: 413,
    ErrorCode.REQUEST_TIMEOUT: 408,
    ErrorCode.CALLBACK_EVENT_DEAD: 409,
    ErrorCode.INTERNAL_ERROR: 500,
}


class GatewayError(Exception):
    """网关业务异常：携带稳定错误码、HTTP 状态与可解释详情。"""

    def __init__(self, code: ErrorCode, message: str, *, status_code: int | None = None,
                 details: dict | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code or _DEFAULT_STATUS.get(code, 400)
        self.details = details or {}


def register_exception_handlers(app: FastAPI) -> None:
    """把 GatewayError 与未预期异常统一转为结构化 JSON。"""

    @app.exception_handler(GatewayError)
    async def _handle_gateway_error(_request: Request, exc: GatewayError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code.value, "message": exc.message,
                               "details": exc.details}},
        )

    @app.exception_handler(Exception)
    async def _handle_unknown(_request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={"error": {"code": ErrorCode.INTERNAL_ERROR.value,
                               "message": "internal error", "details": {}}},
        )
