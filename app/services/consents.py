"""同意状态机：创建 -> 授权 -> 撤销/到期，历史只追加。

合法流转：
    PENDING    -> AUTHORIZED / REVOKED / EXPIRED
    AUTHORIZED -> REVOKED / EXPIRED
    REVOKED / EXPIRED 为终态，任何进一步流转均拒绝。

每次状态变更先在存储锁内完成对象替换，再写审计；审计失败时回滚内存变更，
保证不出现“状态已变、无审计”的半更新。历史记录仅追加，绝不覆盖。
"""
from __future__ import annotations

import copy
import uuid

from app.errors import ErrorCode, GatewayError
from app.logging_utils import get_logger
from app.models import Consent, ConsentHistoryEntry, ConsentStatus

logger = get_logger("consents")

ALLOWED_TRANSITIONS: dict[ConsentStatus, set[ConsentStatus]] = {
    ConsentStatus.PENDING: {ConsentStatus.AUTHORIZED, ConsentStatus.EXPIRED,
                            ConsentStatus.REVOKED},
    ConsentStatus.AUTHORIZED: {ConsentStatus.REVOKED, ConsentStatus.EXPIRED},
    ConsentStatus.REVOKED: set(),
    ConsentStatus.EXPIRED: set(),
}

# scope -> 资源访问时要求该 scope 出现在同意中
SCOPE_FOR_RESOURCE = {
    "balances": "balances",
    "transactions": "transactions",
    "payment": "payment",
}


class ConsentService:
    def __init__(self, storage, audit, settings, clock) -> None:  # noqa: ANN001
        self.storage = storage
        self.audit = audit
        self.settings = settings
        self.clock = clock

    # ---- 内部工具 ------------------------------------------------------
    def _get_owned(self, tenant_id: str, consent_id: str) -> Consent:
        with self.storage.lock:
            consent = self.storage.consents.get(consent_id)
            if consent is None:
                raise GatewayError(ErrorCode.CONSENT_NOT_FOUND,
                                   f"同意不存在: {consent_id}", status_code=404)
            if consent.tenant_id != tenant_id:
                # 跨租户访问按租户隔离拒绝，且不暴露资源是否存在
                raise GatewayError(ErrorCode.TENANT_MISMATCH,
                                   "同意不属于该租户，访问被隔离拒绝")
            return consent

    def _transition(self, consent_id: str, target: ConsentStatus, reason: str,
                    actor: str) -> Consent:
        """在锁内校验流转并暂存变更；审计成功后提交，失败回滚。"""
        with self.storage.lock:
            consent = self.storage.consents.get(consent_id)
            if consent is None:
                raise GatewayError(ErrorCode.CONSENT_NOT_FOUND,
                                   f"同意不存在: {consent_id}", status_code=404)
            before = copy.deepcopy(consent)
            current = consent.status
            if target not in ALLOWED_TRANSITIONS[current]:
                self._invalid_transition(consent, current, target, actor)
            consent.status = target
            entry = ConsentHistoryEntry(
                at=self.clock.now(), action=target.value,
                from_status=current.value, to_status=target.value,
                reason=reason, actor=actor)
            consent.history.append(entry)
            if target == ConsentStatus.AUTHORIZED:
                consent.authorized_at = self.clock.now()
            if target == ConsentStatus.REVOKED:
                consent.revoked_at = self.clock.now()
                consent.revoke_reason = reason
            try:
                self.audit.write(
                    consent.tenant_id, f"consent_{target.value}", "state_change",
                    f"同意 {consent_id}: {current.value} -> {target.value}"
                    + (f" ({reason})" if reason else ""),
                    {"consent_id": consent_id, "from": current.value,
                     "to": target.value, "actor": actor})
            except Exception:
                # 审计落地失败：回滚业务状态，避免静默半更新
                self.storage.consents[consent_id] = before
                raise
            return consent

    def _invalid_transition(self, consent: Consent, current: ConsentStatus,
                            target: ConsentStatus, actor: str) -> None:
        self.audit.write(
            consent.tenant_id, "consent_transition_denied", "denied",
            f"非法流转 {current.value} -> {target.value}",
            {"consent_id": consent.consent_id, "from": current.value,
             "to": target.value, "actor": actor})
        raise GatewayError(ErrorCode.CONSENT_INVALID_TRANSITION,
                           f"同意状态 {current.value} 不允许流转到 {target.value}",
                           details={"from": current.value, "to": target.value})

    # ---- 生命周期 ------------------------------------------------------
    def create(self, tenant_id: str, scopes: list[str], account_ids: list[str],
               ttl_seconds: int) -> Consent:
        if not scopes:
            raise GatewayError(ErrorCode.SCOPE_INSUFFICIENT, "创建同意至少需要一个作用域")
        if len(scopes) > self.settings.max_scopes:
            raise GatewayError(ErrorCode.PAYLOAD_TOO_LARGE,
                               f"作用域数量超过上限 {self.settings.max_scopes}")
        if len(account_ids) > self.settings.max_accounts_per_consent:
            raise GatewayError(ErrorCode.PAYLOAD_TOO_LARGE,
                               f"账户数量超过上限 "
                               f"{self.settings.max_accounts_per_consent}")
        if ttl_seconds <= 0:
            raise GatewayError(ErrorCode.PAYLOAD_TOO_LARGE,
                               "ttl_seconds 必须为正数")
        consent_id = "cs-" + uuid.uuid4().hex[:12]
        now = self.clock.now()
        consent = Consent(
            consent_id=consent_id, tenant_id=tenant_id, scopes=list(scopes),
            account_ids=list(account_ids), status=ConsentStatus.PENDING,
            created_at=now, expires_at=now + ttl_seconds,
            history=[ConsentHistoryEntry(at=now, action="created",
                                         from_status=None, to_status="pending",
                                         actor=tenant_id)],
        )
        with self.storage.lock:
            self.storage.consents[consent_id] = consent
            snapshot = copy.deepcopy(consent)
            try:
                self.audit.write(tenant_id, "consent_created", "state_change",
                                 f"创建同意 {consent_id} scopes={scopes}",
                                 {"consent_id": consent_id, "scopes": list(scopes),
                                  "account_ids": list(account_ids),
                                  "expires_at": consent.expires_at})
            except Exception:
                del self.storage.consents[consent_id]
                raise
        logger.info("consent created id=%s tenant=%s", consent_id, tenant_id)
        return snapshot

    def authorize(self, tenant_id: str, consent_id: str) -> Consent:
        consent = self._get_owned(tenant_id, consent_id)
        result = self._transition(consent_id, ConsentStatus.AUTHORIZED, "", tenant_id)
        logger.info("consent authorized id=%s tenant=%s", consent_id, tenant_id)
        return result

    def revoke(self, tenant_id: str, consent_id: str, reason: str = "") -> Consent:
        self._get_owned(tenant_id, consent_id)
        result = self._transition(consent_id, ConsentStatus.REVOKED, reason, tenant_id)
        logger.info("consent revoked id=%s reason=%s", consent_id, reason)
        return result

    def expire_due(self) -> int:
        """到期扫描：将已过 expires_at 的 PENDING/AUTHORIZED 同意置为 EXPIRED。"""
        now = self.clock.now()
        with self.storage.lock:
            due = [c for c in self.storage.consents.values()
                   if c.status in (ConsentStatus.PENDING, ConsentStatus.AUTHORIZED)
                   and c.expires_at <= now]
        for consent in due:
            self._transition(consent.consent_id, ConsentStatus.EXPIRED,
                             "到期自动流转", "system")
        if due:
            logger.info("expired %d due consents", len(due))
        return len(due)

    # ---- 资源访问校验 --------------------------------------------------
    def get_for_access(self, tenant_id: str, consent_id: str, scope: str,
                       account_id: str | None) -> Consent:
        """资源访问前校验：存在性/租户归属/状态/作用域/账户授权。"""
        with self.storage.lock:
            consent = self.storage.consents.get(consent_id)
            if consent is None:
                raise GatewayError(ErrorCode.CONSENT_NOT_FOUND,
                                   f"同意不存在: {consent_id}", status_code=404)
            if consent.tenant_id != tenant_id:
                self.audit.write(tenant_id, "resource_access", "denied",
                                 ErrorCode.TENANT_MISMATCH.value,
                                 {"consent_id": consent_id,
                                  "consent_tenant": consent.tenant_id,
                                  "actor_tenant": tenant_id, "scope": scope})
                raise GatewayError(ErrorCode.TENANT_MISMATCH,
                                   "同意不属于该租户，访问被隔离拒绝")
            if consent.status == ConsentStatus.REVOKED:
                self._access_denied(consent, ErrorCode.CONSENT_REVOKED,
                                    "同意已撤销，资源访问被拒绝", scope, account_id)
            if consent.status == ConsentStatus.EXPIRED:
                self._access_denied(consent, ErrorCode.CONSENT_EXPIRED,
                                    "同意已到期，资源访问被拒绝", scope, account_id)
            if consent.status != ConsentStatus.AUTHORIZED:
                self._access_denied(consent, ErrorCode.CONSENT_INVALID_TRANSITION,
                                    f"同意尚未授权（{consent.status.value}）",
                                    scope, account_id)
            if consent.expires_at <= self.clock.now():
                # 防御：即使扫描尚未运行，过期同意也不得放行
                self._access_denied(consent, ErrorCode.CONSENT_EXPIRED,
                                    "同意已到期，资源访问被拒绝", scope, account_id)
            required = SCOPE_FOR_RESOURCE.get(scope, scope)
            if required not in consent.scopes:
                self._access_denied(consent, ErrorCode.CONSENT_SCOPE_INSUFFICIENT,
                                    f"同意缺少作用域 {required}", scope, account_id)
            if account_id is not None and consent.account_ids and \
                    account_id not in consent.account_ids:
                self._access_denied(consent, ErrorCode.CONSENT_RESOURCE_FORBIDDEN,
                                    f"账户 {account_id} 不在同意授权范围内",
                                    scope, account_id)
            self.audit.write(tenant_id, "resource_access", "allowed",
                             f"同意 {consent_id} 允许 scope={scope}",
                             {"consent_id": consent_id, "scope": scope,
                              "account_id": account_id})
            return copy.deepcopy(consent)

    def _access_denied(self, consent: Consent, code: ErrorCode, message: str,
                       scope: str, account_id: str | None) -> None:
        self.audit.write(consent.tenant_id, "resource_access", "denied",
                         f"{code.value}: {message}",
                         {"consent_id": consent.consent_id, "status": consent.status.value,
                          "scope": scope, "account_id": account_id})
        raise GatewayError(code, message,
                           details={"consent_id": consent.consent_id,
                                    "status": consent.status.value})

    def get(self, tenant_id: str, consent_id: str) -> Consent:
        return self._get_owned(tenant_id, consent_id)
