"""领域模型与状态机：租户、密钥、凭证、访问令牌、同意、回调、审计。"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class KeyStatus(enum.Enum):
    ACTIVE = "active"
    RETIRED = "retired"


class ConsentStatus(enum.Enum):
    PENDING = "pending"
    AUTHORISED = "authorised"
    REVOKED = "revoked"
    EXPIRED = "expired"


class CallbackStatus(enum.Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"


class AmendmentStatus(enum.Enum):
    """同意变更申请的生命周期。

    PENDING  待生效（审批前）：原作用域/有效期照常可用；
    APPROVED 已批准：新作用域/有效期已正式生效；
    REJECTED 已拒绝（审批方显式驳回）；
    VOIDED   已作废：待生效期间同意被撤销或到期，按最终状态算，变更随之作废。
    """

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    VOIDED = "voided"


@dataclass
class ApiKey:
    key_id: str
    tenant_id: str
    secret_hash: str
    scopes: list[str]
    status: KeyStatus
    expires_at: float | None
    issued_at: float


@dataclass
class Tenant:
    tenant_id: str
    name: str


@dataclass
class AccessToken:
    token: str
    tenant_id: str
    key_id: str
    scopes: list[str]
    issued_at: float
    expires_at: float
    alg: str


@dataclass
class Consent:
    consent_id: str
    tenant_id: str
    resource: str
    scopes: list[str]
    ttl_seconds: float
    status: ConsentStatus
    version: int
    created_at: float
    authorised_at: float | None
    expires_at: float | None
    revoked_at: float | None
    history: list[dict] = field(default_factory=list)
    amendments: list[dict] = field(default_factory=list)


_ALLOWED_CONSENT_TRANSITIONS: dict[ConsentStatus, set[ConsentStatus]] = {
    ConsentStatus.PENDING: {ConsentStatus.AUTHORISED, ConsentStatus.REVOKED, ConsentStatus.EXPIRED},
    ConsentStatus.AUTHORISED: {ConsentStatus.REVOKED, ConsentStatus.EXPIRED},
    ConsentStatus.REVOKED: set(),
    ConsentStatus.EXPIRED: set(),
}


def can_transition(current: ConsentStatus, target: ConsentStatus) -> bool:
    raise NotImplementedError


def can_transition(current: ConsentStatus, target: ConsentStatus) -> bool:
    """判断同意状态流转是否合法。

    合法路径：
      PENDING    -> AUTHORISED / REVOKED / EXPIRED
      AUTHORISED -> REVOKED / EXPIRED
      REVOKED / EXPIRED 为终态，不可再流转。
    """
    return target in _ALLOWED_CONSENT_TRANSITIONS.get(current, set())
