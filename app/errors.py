"""可区分错误码的领域异常定义。"""
from __future__ import annotations


class GatewayError(Exception):
    """所有网关业务错误的基类。"""

    code: str = "gateway_error"
    status_code: int = 400

    def __init__(self, message: str = "", *, tenant_id: str | None = None) -> None:
        super().__init__(message or self.code)
        self.message = message or self.code
        self.tenant_id = tenant_id


class AuthError(GatewayError):
    code = "auth_error"
    status_code = 401


class ScopeInsufficientError(AuthError):
    code = "scope_insufficient"
    status_code = 403


class CredentialMissingError(AuthError):
    code = "credential_missing"


class CredentialUnknownError(AuthError):
    code = "credential_unknown"


class CredentialBadSecretError(AuthError):
    code = "credential_bad_secret"


class CredentialRevokedError(AuthError):
    code = "credential_revoked"


class CredentialExpiredError(AuthError):
    code = "credential_expired"


class TokenError(GatewayError):
    code = "token_error"
    status_code = 401


class TokenMalformedError(TokenError):
    code = "token_malformed"


class TokenAlgorithmNotAllowedError(TokenError):
    code = "token_algorithm_not_allowed"


class TokenKeyUnknownError(TokenError):
    code = "token_key_unknown"


class TokenKeyRetiredError(TokenError):
    code = "token_key_retired"


class TokenBadSignatureError(TokenError):
    code = "token_bad_signature"


class TokenExpiredError(TokenError):
    code = "token_expired"


class ConsentStateError(GatewayError):
    code = "consent_invalid_transition"
    status_code = 409


class NotFoundError(GatewayError):
    code = "not_found"
    status_code = 404


class ConsentNotFoundError(NotFoundError):
    code = "consent_not_found"


class ConsentAccessError(GatewayError):
    code = "consent_access_denied"
    status_code = 403


class ConsentRevokedError(ConsentAccessError):
    code = "consent_revoked"


class ConsentExpiredError(ConsentAccessError):
    code = "consent_expired"


class ConsentResourceMismatchError(ConsentAccessError):
    code = "consent_resource_mismatch"


class RateLimitError(GatewayError):
    code = "rate_limited"
    status_code = 429


class PayloadTooLargeError(GatewayError):
    code = "payload_too_large"
    status_code = 413


class TimeoutLimitError(GatewayError):
    code = "timeout_limit_exceeded"
    status_code = 408


class AuditWriteError(GatewayError):
    code = "audit_write_failed"
    status_code = 500


class CallbackNotFoundError(NotFoundError):
    code = "callback_not_found"


class ValidationError(GatewayError):
    code = "validation_error"
    status_code = 400


class ConsentScopeMissingError(ConsentAccessError):
    code = "consent_scope_missing"


class ConsentNotAuthorisedError(ConsentAccessError):
    code = "consent_not_authorised"


class CallbackPayloadTooLargeError(PayloadTooLargeError):
    code = "callback_payload_too_large"


class ConsentAmendmentError(GatewayError):
    """同意变更相关错误的基类。"""

    code = "consent_amendment_error"
    status_code = 409


class ConsentAmendmentNotFoundError(NotFoundError):
    code = "consent_amendment_not_found"


class ConsentAmendmentPendingError(ConsentAmendmentError):
    """已有待生效变更，不允许重复提交。"""

    code = "consent_amendment_pending"


class ConsentAmendmentNotPendingError(ConsentAmendmentError):
    """变更已不在待生效状态（已批准/已拒绝/已作废）。"""

    code = "consent_amendment_not_pending"


class ConsentAmendmentNoChangeError(ValidationError):
    """变更请求既未追加作用域也未延长有效期。"""

    code = "consent_amendment_no_change"


class ConsentAmendmentInvalidStateError(ConsentAmendmentError):
    """同意当前状态不允许申请变更（未授权/已撤销/已到期）。"""

    code = "consent_amendment_invalid_state"


class IdempotencyReplayMismatchError(GatewayError):
    """同一幂等键重复提交但请求体与首次不一致。"""

    code = "idempotency_replay_mismatch"
    status_code = 409


class BatchRequestError(ValidationError):
    """批量请求整体不合法（空批次、动作未知等），整批未执行。"""

    code = "batch_request_invalid"
