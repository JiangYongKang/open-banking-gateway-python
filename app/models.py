"""领域数据模型（纯类型定义）。"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class KeyState(str, Enum):
    ACTIVE = "active"      # 可签发、可验签
    RETIRED = "retired"    # 仅保留历史记录，验签必须被拒绝（密钥已退役）


class ConsentStatus(str, Enum):
    PENDING = "pending"
    AUTHORIZED = "authorized"
    REVOKED = "revoked"
    EXPIRED = "expired"


class CallbackStatus(str, Enum):
    PENDING = "pending"      # 尚未首次投递
    RETRYING = "retrying"    # 投递失败，退避等待中
    DELIVERED = "delivered"
    DEAD = "dead"            # 超过最大重试，可查询的最终失败态


class LimitAction(str, Enum):
    REJECT = "reject"        # 立即拒绝并返回等待信息
    DELAY = "delay"          # 在超时上限内等待后重试获取，否则拒绝


@dataclass
class SigningKey:
    kid: str
    alg: str
    secret: str
    state: KeyState
    created_at: float
    retired_at: float | None = None


@dataclass
class PartnerCredential:
    credential_id: str
    tenant_id: str
    secret: str
    scopes: list[str]
    revoked: bool
    expires_at: float          # UNIX 时间戳；0 表示不过期


@dataclass
class TokenClaims:
    jti: str
    tenant_id: str
    credential_id: str
    scopes: list[str]
    kid: str
    alg: str
    iat: float
    exp: float


@dataclass
class ConsentHistoryEntry:
    at: float
    action: str                # created / authorized / revoked / expired
    from_status: str | None
    to_status: str
    reason: str = ""
    actor: str = ""            # tenant_id 或 system


@dataclass
class Consent:
    consent_id: str
    tenant_id: str
    scopes: list[str]
    account_ids: list[str]
    status: ConsentStatus
    created_at: float
    expires_at: float
    authorized_at: float | None = None
    revoked_at: float | None = None
    revoke_reason: str = ""
    history: list[ConsentHistoryEntry] = field(default_factory=list)


@dataclass
class WindowCounter:
    window_start: float
    value: int


@dataclass
class CallbackEvent:
    event_id: str
    tenant_id: str
    callback_url: str
    payload: dict
    status: CallbackStatus
    attempts: int = 0
    max_attempts: int = 5
    created_at: float = 0.0
    next_attempt_at: float = 0.0
    last_error: str = ""
    delivered_at: float | None = None
    attempt_history: list[dict] = field(default_factory=list)
    in_flight: bool = False    # 投递占用标记，保证重试互不串状态


@dataclass
class AuditEntry:
    audit_id: str
    at: float
    tenant_id: str
    action: str
    result: str                # allowed / denied / state_change / info
    reason: str
    masked_context: dict
