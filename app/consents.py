"""同意生命周期服务。

状态机：
    PENDING --authorise--> AUTHORISED --revoke/expire--> REVOKED/EXPIRED
    PENDING 也可直接 revoke/expire；REVOKED、EXPIRED 为终态。

保证：
* 每次流转在同一跨集合事务中同时更新 consent 记录（含 version+1 与 history 追加）
  与审计记录，审计写失败则整体不落地，不存在半更新；
* history 仅追加，旧版本永不覆盖丢失；
* 撤销/到期后资源访问被明确拒绝（原因可区分）。
"""
from __future__ import annotations

import time
import uuid

from .audit import make_entry
from .errors import (
    ConsentExpiredError,
    ConsentNotAuthorisedError,
    ConsentNotFoundError,
    ConsentResourceMismatchError,
    ConsentRevokedError,
    ConsentScopeMissingError,
    ConsentStateError,
    ValidationError,
)
from .models import ConsentStatus, can_transition


def _new_consent_id() -> str:
    return "consent-" + uuid.uuid4().hex[:16]


class ConsentService:
    def __init__(self, store, audit=None, *, clock=time.time) -> None:
        self._store = store
        self._audit = audit
        self._clock = clock
        # 由 runtime 注入：同意进入终态时在同事务内作废待生效变更
        self.amendment_void_hook = None

    # ---- 内部：事务内流转 ------------------------------------------------

    def _transition(self, tenant_id: str, consent_id: str, target: ConsentStatus, action: str) -> dict:
        now = self._clock()
        coll_names = ["consents", "audit"]
        if self.amendment_void_hook is not None and target in (
            ConsentStatus.REVOKED, ConsentStatus.EXPIRED
        ):
            coll_names.append("amendments")

        def _tx(consents, audit, amendments=None):
            rec = consents.get(consent_id)
            if rec is None or rec["tenant_id"] != tenant_id:
                # 注意：先校验归属，不泄漏其它租户同意是否存在
                raise ConsentNotFoundError(f"同意 {consent_id!r} 不存在", tenant_id=tenant_id)
            current = ConsentStatus(rec["status"])
            if not can_transition(current, target):
                if self._audit is not None:
                    eid, entry = make_entry(
                        action,
                        tenant_id=tenant_id,
                        result="denied",
                        detail={"consent_id": consent_id, "from": current.value, "to": target.value,
                                "reason": "invalid_transition"},
                        clock=self._clock,
                    )
                    audit.put(eid, entry)
                raise ConsentStateError(
                    f"非法状态流转: {current.value} -> {target.value}", tenant_id=tenant_id
                )
            event = {"ts": now, "from": current.value, "to": target.value, "action": action}
            rec["status"] = target.value
            rec["version"] += 1
            rec["history"].append(event)
            if target is ConsentStatus.AUTHORISED:
                rec["authorised_at"] = now
                rec["expires_at"] = now + rec["ttl_seconds"]
            elif target is ConsentStatus.REVOKED:
                rec["revoked_at"] = now
            elif target is ConsentStatus.EXPIRED:
                rec["expires_at"] = now
            # 变更待生效期间同意终态化：同一事务内把待生效变更作废，
            # 保证“先撤销/到期，后批准”绝不可能让新作用域生效。
            voided: list[str] = []
            if amendments is not None and self.amendment_void_hook is not None:
                reason = "consent_revoked" if target is ConsentStatus.REVOKED else "consent_expired"
                voided = self.amendment_void_hook(
                    consents, amendments, audit, consent_id, reason, now
                )
            consents.put(consent_id, rec)
            if self._audit is not None:
                eid, entry = make_entry(
                    action,
                    tenant_id=tenant_id,
                    result="state_change",
                    detail={"consent_id": consent_id, "from": current.value, "to": target.value,
                            "version": rec["version"], "amendments_voided": voided},
                    clock=self._clock,
                )
                audit.put(eid, entry)
            return rec

        return self._store.atomic(coll_names, _tx)

    # ---- 公开 API --------------------------------------------------------

    def create(
        self,
        tenant_id: str,
        resource: str,
        scopes: list[str],
        ttl_seconds: float,
    ) -> dict:
        if not resource or not isinstance(resource, str):
            raise ValidationError("resource 不能为空", tenant_id=tenant_id)
        if not scopes:
            raise ValidationError("scopes 至少包含一个作用域", tenant_id=tenant_id)
        if ttl_seconds is None or ttl_seconds <= 0:
            raise ValidationError("ttl_seconds 必须为正数", tenant_id=tenant_id)
        now = self._clock()
        consent_id = _new_consent_id()
        record = {
            "consent_id": consent_id,
            "tenant_id": tenant_id,
            "resource": resource,
            "scopes": list(scopes),
            "ttl_seconds": float(ttl_seconds),
            "status": ConsentStatus.PENDING.value,
            "version": 1,
            "created_at": now,
            "authorised_at": None,
            "expires_at": None,
            "revoked_at": None,
            "versions": [],
            "history": [{"ts": now, "from": None, "to": ConsentStatus.PENDING.value,
                         "action": "create"}],
        }

        def _tx(consents, audit):
            consents.put(consent_id, record)
            if self._audit is not None:
                eid, entry = make_entry(
                    "consent_create",
                    tenant_id=tenant_id,
                    result="state_change",
                    detail={"consent_id": consent_id, "resource": resource, "scopes": list(scopes)},
                    clock=self._clock,
                )
                audit.put(eid, entry)

        self._store.atomic(["consents", "audit"], _tx)
        return record

    def authorise(self, tenant_id: str, consent_id: str) -> dict:
        return self._transition(tenant_id, consent_id, ConsentStatus.AUTHORISED, "consent_authorise")

    def revoke(self, tenant_id: str, consent_id: str) -> dict:
        return self._transition(tenant_id, consent_id, ConsentStatus.REVOKED, "consent_revoke")

    def expire_due(self, now: float | None = None) -> list[str]:
        """扫描所有已授权且到期的同意并置为 EXPIRED，返回处理的 id 列表。"""
        current = self._clock() if now is None else now
        due = [
            rec
            for rec in self._store.collection("consents").list_items()
            if rec["status"] == ConsentStatus.AUTHORISED.value
            and rec.get("expires_at") is not None
            and rec["expires_at"] <= current
        ]
        expired = []
        for rec in due:
            self._transition(rec["tenant_id"], rec["consent_id"], ConsentStatus.EXPIRED, "consent_expire")
            expired.append(rec["consent_id"])
        return expired

    def get(self, tenant_id: str, consent_id: str) -> dict:
        rec = self._store.collection("consents").get(consent_id)
        if rec is None or rec["tenant_id"] != tenant_id:
            raise ConsentNotFoundError(f"同意 {consent_id!r} 不存在", tenant_id=tenant_id)
        return rec

    def check_access(
        self,
        tenant_id: str,
        consent_id: str,
        resource: str,
        scope: str,
    ) -> dict:
        """资源访问前的同意闸门。撤销/到期/资源不符/作用域不足分别给出不同错误码。"""
        rec = self.get(tenant_id, consent_id)
        status = ConsentStatus(rec["status"])

        def _deny(err, reason: str):
            if self._audit is not None:
                self._audit.record(
                    "consent_access",
                    tenant_id=tenant_id,
                    result="denied",
                    detail={"consent_id": consent_id, "resource": resource, "scope": scope,
                            "reason": reason},
                )
            raise err(f"访问被拒绝: {reason}", tenant_id=tenant_id)

        if status is ConsentStatus.REVOKED:
            _deny(ConsentRevokedError, "consent_revoked")
        if status is ConsentStatus.EXPIRED:
            _deny(ConsentExpiredError, "consent_expired")
        if status is not ConsentStatus.AUTHORISED:
            _deny(ConsentNotAuthorisedError, "consent_not_authorised")
        if rec["resource"] != resource:
            _deny(ConsentResourceMismatchError, "consent_resource_mismatch")
        if scope not in rec["scopes"]:
            _deny(ConsentScopeMissingError, "consent_scope_missing")

        now = self._clock()
        if rec.get("expires_at") is not None and rec["expires_at"] <= now:
            # 兜底：即使扫描器尚未运行，到期后也绝不放行
            self._transition(tenant_id, consent_id, ConsentStatus.EXPIRED, "consent_expire")
            _deny(ConsentExpiredError, "consent_expired")
        return rec
