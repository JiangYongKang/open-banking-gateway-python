"""同意生命周期服务，含同意变更（amendment）支持。

状态机：
    PENDING --authorise--> AUTHORISED --revoke/expire--> REVOKED/EXPIRED
    PENDING 也可直接 revoke/expire；REVOKED、EXPIRED 为终态。

变更生命周期（仅 AUTHORISED 同意可申请）：
    request_amendment -> PENDING（待生效），审批通过前原 scopes/expires_at 不变；
    approve  -> APPROVED，新作用域与延长后的有效期才正式生效；
    reject   -> REJECTED（显式驳回，原授权不受影响）；
    变更待生效期间同意被撤销/到期 -> 变更在同一事务内 VOIDED，按终态算，
    此后新作用域绝不可能放行访问。

保证：
* 每次流转在同一跨集合事务中同时更新 consent 记录（含 version+1 与 history 追加）
  与审计记录，审计写失败则整体不落地，不存在半更新；
* history / amendments / revisions 均仅追加，旧版本永不覆盖丢失，每次变更都带
  变更前后的完整快照，可逐条追溯；
* 撤销/到期后资源访问被明确拒绝（原因可区分）。
"""
from __future__ import annotations

import time
import uuid

from .audit import make_entry
from .errors import (
    ConsentAmendmentInvalidStateError,
    ConsentAmendmentNoChangeError,
    ConsentAmendmentNotFoundError,
    ConsentAmendmentNotPendingError,
    ConsentAmendmentPendingError,
    ConsentExpiredError,
    ConsentNotAuthorisedError,
    ConsentNotFoundError,
    ConsentResourceMismatchError,
    ConsentRevokedError,
    ConsentScopeMissingError,
    ConsentStateError,
    ValidationError,
)
from .models import AmendmentStatus, ConsentStatus, can_transition


def _new_consent_id() -> str:
    return "consent-" + uuid.uuid4().hex[:16]


def _new_amendment_id() -> str:
    return "amd-" + uuid.uuid4().hex[:16]


def _audit_put(audit, action, tenant_id, result, detail, clock) -> None:
    if audit is not None:
        eid, entry = make_entry(
            action, tenant_id=tenant_id, result=result, detail=detail, clock=clock
        )
        audit.put(eid, entry)


def _snapshot_scopes_expiry(rec: dict) -> dict:
    return {
        "scopes": list(rec["scopes"]),
        "expires_at": rec.get("expires_at"),
        "ttl_seconds": rec.get("ttl_seconds"),
        "version": rec["version"],
    }


class ConsentService:
    def __init__(self, store, audit=None, *, clock=time.time) -> None:
        self._store = store
        self._audit = audit
        self._clock = clock

    # =====================================================================
    # 事务内原语（locked helpers）：操作传入的 proxy，不自行加锁/开事务，
    # 供本服务的公开方法与批量服务 BatchService 在同一事务内复用。
    # audit proxy 可能为 None；now 由调用方统一给定。
    # =====================================================================

    def _load_tenant_consent(self, consents, tenant_id: str, consent_id: str) -> dict:
        rec = consents.get(consent_id)
        if rec is None or rec["tenant_id"] != tenant_id:
            # 注意：先校验归属，跨租户访问与不存在同等处理，不泄漏存在性
            raise ConsentNotFoundError(
                f"同意 {consent_id!r} 不存在", tenant_id=tenant_id
            )
        return rec

    def transition_locked(self, consents, audit, tenant_id, consent_id,
                          target: ConsentStatus, now: float,
                          *, action: str | None = None) -> dict:
        rec = self._load_tenant_consent(consents, tenant_id, consent_id)
        current = ConsentStatus(rec["status"])
        action = action or f"consent_{target.value}"
        if not can_transition(current, target):
            _audit_put(
                audit, action, tenant_id, "denied",
                {"consent_id": consent_id, "from": current.value,
                 "to": target.value, "reason": "invalid_transition"},
                self._clock,
            )
            raise ConsentStateError(
                f"非法状态流转: {current.value} -> {target.value}", tenant_id=tenant_id
            )
        # 待生效变更遇撤销/到期：同一事务内作废，之后新作用域不可能再生效
        self._void_pending_amendments_locked(audit, rec, now, reason=f"consent_{target.value}")
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
        consents.put(consent_id, rec)
        _audit_put(
            audit, action, tenant_id, "state_change",
            {"consent_id": consent_id, "from": current.value,
             "to": target.value, "version": rec["version"]},
            self._clock,
        )
        return rec

    def create_locked(self, consents, audit, tenant_id, resource, scopes,
                      ttl_seconds: float, now: float) -> dict:
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
            "history": [{"ts": now, "from": None, "to": ConsentStatus.PENDING.value,
                         "action": "create"}],
            "amendments": [],
            "revisions": [],
        }
        consents.put(consent_id, record)
        _audit_put(
            audit, "consent_create", tenant_id, "state_change",
            {"consent_id": consent_id, "resource": resource, "scopes": list(scopes)},
            self._clock,
        )
        return record

    def request_amendment_locked(self, consents, audit, tenant_id, consent_id,
                                 add_scopes, extend_ttl_seconds, now: float) -> dict:
        rec = self._load_tenant_consent(consents, tenant_id, consent_id)
        current = ConsentStatus(rec["status"])
        if current is not ConsentStatus.AUTHORISED:
            _audit_put(
                audit, "consent_amendment_request", tenant_id, "denied",
                {"consent_id": consent_id, "status": current.value,
                 "reason": "consent_not_authorised_for_amendment"},
                self._clock,
            )
            raise ConsentAmendmentInvalidStateError(
                f"同意当前状态 {current.value} 不允许申请变更，仅 AUTHORISED 可申请",
                tenant_id=tenant_id,
            )
        if any(
            a["status"] == AmendmentStatus.PENDING.value
            for a in rec.get("amendments", [])
        ):
            _audit_put(
                audit, "consent_amendment_request", tenant_id, "denied",
                {"consent_id": consent_id, "reason": "amendment_already_pending"},
                self._clock,
            )
            raise ConsentAmendmentPendingError(
                "该同意已有待生效变更，请先审批或驳回后再提交", tenant_id=tenant_id
            )
        before = _snapshot_scopes_expiry(rec)
        merged_scopes = list(dict.fromkeys(list(rec["scopes"]) + list(add_scopes)))
        amendment_id = _new_amendment_id()
        amendment = {
            "amendment_id": amendment_id,
            "consent_id": consent_id,
            "tenant_id": tenant_id,
            "status": AmendmentStatus.PENDING.value,
            "add_scopes": list(add_scopes),
            "extend_ttl_seconds": float(extend_ttl_seconds),
            "proposed_scopes": merged_scopes,
            "requested_at": now,
            "decided_at": None,
            "before": before,
            "after": None,
            "decide_history": [],
        }
        rec.setdefault("amendments", []).append(amendment)
        # 申请本身也记一个版本事件：旧 scopes/expires_at 原样保留，业务不受影响
        rec["version"] += 1
        rec["history"].append({
            "ts": now, "from": current.value, "to": current.value,
            "action": "consent_amendment_request",
            "amendment_id": amendment_id,
            "add_scopes": list(add_scopes),
            "extend_ttl_seconds": float(extend_ttl_seconds),
        })
        consents.put(consent_id, rec)
        _audit_put(
            audit, "consent_amendment_request", tenant_id, "state_change",
            {"consent_id": consent_id, "amendment_id": amendment_id,
             "add_scopes": list(add_scopes),
             "extend_ttl_seconds": float(extend_ttl_seconds),
             "status": AmendmentStatus.PENDING.value},
            self._clock,
        )
        return {"consent": rec, "amendment": amendment}

    def decide_amendment_locked(self, consents, audit, tenant_id, consent_id,
                                amendment_id, approve: bool, now: float) -> dict:
        rec = self._load_tenant_consent(consents, tenant_id, consent_id)
        amendment = next(
            (a for a in rec.get("amendments", [])
             if a["amendment_id"] == amendment_id),
            None,
        )
        if amendment is None:
            raise ConsentAmendmentNotFoundError(
                f"变更 {amendment_id!r} 不存在", tenant_id=tenant_id
            )
        if amendment["status"] != AmendmentStatus.PENDING.value:
            raise ConsentAmendmentNotPendingError(
                f"变更已 {amendment['status']}，不可再次审批", tenant_id=tenant_id
            )
        current = ConsentStatus(rec["status"])
        before = _snapshot_scopes_expiry(rec)
        if approve:
            if current is not ConsentStatus.AUTHORISED:
                # 待生效期间同意已终态化：作废已在 revoke/expire 的同一事务内落盘，
                # 这里直接拒绝（本事务随即回滚，不产生任何写入），
                # 绝不允许在终态同意上让新作用域生效。
                raise ConsentAmendmentNotPendingError(
                    f"同意已 {current.value}，待生效变更已随之作废，"
                    f"不能再批准",
                    tenant_id=tenant_id,
                )
            amendment["status"] = AmendmentStatus.APPROVED.value
            amendment["decided_at"] = now
            # 新作用域：原作用域 ∪ 追加作用域（去重保序）
            rec["scopes"] = list(
                dict.fromkeys(list(rec["scopes"]) + list(amendment["add_scopes"]))
            )
            # 延长有效期：从当前到期时间（兜底取当前时刻）往后顺延
            base = rec.get("expires_at")
            if base is None or base < now:
                base = now
            rec["expires_at"] = base + amendment["extend_ttl_seconds"]
            rec["ttl_seconds"] = float(rec.get("ttl_seconds", 0.0)) + \
                amendment["extend_ttl_seconds"]
            event_action = "consent_amendment_approve"
            result_detail = {
                "consent_id": consent_id, "amendment_id": amendment_id,
                "scopes": list(rec["scopes"]), "expires_at": rec["expires_at"],
            }
        else:
            amendment["status"] = AmendmentStatus.REJECTED.value
            amendment["decided_at"] = now
            event_action = "consent_amendment_reject"
            result_detail = {"consent_id": consent_id, "amendment_id": amendment_id}
        amendment["after"] = _snapshot_scopes_expiry(rec)
        amendment["decide_history"].append({
            "ts": now, "decision": amendment["status"],
            "before": before, "after": _snapshot_scopes_expiry(rec),
        })
        # 把生效后的完整版本快照存入 revisions，旧版本永不被覆盖
        rec.setdefault("revisions", []).append({
            "ts": now, "amendment_id": amendment_id,
            "event": event_action,
            "scopes": list(rec["scopes"]),
            "expires_at": rec.get("expires_at"),
            "ttl_seconds": rec.get("ttl_seconds"),
            "status": rec["status"],
            "version_before": before["version"],
        })
        rec["version"] += 1
        rec["history"].append({
            "ts": now, "from": current.value, "to": rec["status"],
            "action": event_action, "amendment_id": amendment_id,
        })
        consents.put(consent_id, rec)
        _audit_put(
            audit, event_action, tenant_id, "state_change", result_detail, self._clock
        )
        return {"consent": rec, "amendment": amendment}

    def _void_amendment_locked(self, amendment, rec, now, *, reason) -> None:
        amendment["status"] = AmendmentStatus.VOIDED.value
        amendment["decided_at"] = now
        amendment["after"] = None
        amendment["decide_history"].append({
            "ts": now, "decision": AmendmentStatus.VOIDED.value, "reason": reason,
        })
        # 作废也是一个只增不改的版本事件：version 与 history 长度始终一致
        rec["version"] += 1
        rec["history"].append({
            "ts": now, "from": rec["status"], "to": rec["status"],
            "action": "consent_amendment_void",
            "amendment_id": amendment["amendment_id"], "reason": reason,
        })

    def _void_pending_amendments_locked(self, audit, rec, now, *, reason):
        pending = [
            a for a in rec.get("amendments", [])
            if a["status"] == AmendmentStatus.PENDING.value
        ]
        for amendment in pending:
            self._void_amendment_locked(amendment, rec, now, reason=reason)
            _audit_put(
                audit, "consent_amendment_void", rec["tenant_id"], "state_change",
                {"consent_id": rec["consent_id"],
                 "amendment_id": amendment["amendment_id"], "reason": reason},
                self._clock,
            )
        return pending

    # =====================================================================
    # 公开 API：单个操作各自在独立事务中完成（公开方法不得在已有事务中调用，
    # 批量路径请走 BatchService，避免自嵌套加锁）。
    # =====================================================================

    def _transition(self, tenant_id, consent_id, target: ConsentStatus,
                    action: str) -> dict:
        now = self._clock()

        def _tx(consents, audit):
            return self.transition_locked(
                consents, audit, tenant_id, consent_id, target, now, action=action
            )

        try:
            return self._store.atomic(["consents", "audit"], _tx)
        except ConsentStateError:
            # 拒绝类审计在事务内，随异常回滚不落盘；补一条 denied 审计
            if self._audit is not None:
                self._audit.record(
                    action, tenant_id=tenant_id, result="denied",
                    detail={"consent_id": consent_id, "to": target.value,
                            "reason": "invalid_transition"},
                )
            raise

    @staticmethod
    def _validate_create(resource, scopes, ttl_seconds, tenant_id) -> None:
        if not resource or not isinstance(resource, str):
            raise ValidationError("resource 不能为空", tenant_id=tenant_id)
        if not scopes:
            raise ValidationError("scopes 至少包含一个作用域", tenant_id=tenant_id)
        if ttl_seconds is None or ttl_seconds <= 0:
            raise ValidationError("ttl_seconds 必须为正数", tenant_id=tenant_id)

    def create(self, tenant_id, resource, scopes, ttl_seconds) -> dict:
        self._validate_create(resource, scopes, ttl_seconds, tenant_id)
        now = self._clock()

        def _tx(consents, audit):
            return self.create_locked(
                consents, audit, tenant_id, resource, scopes, float(ttl_seconds), now
            )

        return self._store.atomic(["consents", "audit"], _tx)

    def authorise(self, tenant_id, consent_id) -> dict:
        return self._transition(tenant_id, consent_id,
                                ConsentStatus.AUTHORISED, "consent_authorise")

    def revoke(self, tenant_id, consent_id) -> dict:
        return self._transition(tenant_id, consent_id,
                                ConsentStatus.REVOKED, "consent_revoke")

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
            self._transition(rec["tenant_id"], rec["consent_id"],
                             ConsentStatus.EXPIRED, "consent_expire")
            expired.append(rec["consent_id"])
        return expired

    # ---- 变更公开 API ----------------------------------------------------

    @staticmethod
    def _validate_amendment(add_scopes, extend_ttl_seconds, tenant_id):
        add_scopes = list(add_scopes or [])
        if not all(isinstance(s, str) and s for s in add_scopes):
            raise ValidationError("add_scopes 必须是非空字符串列表",
                                  tenant_id=tenant_id)
        extend = float(extend_ttl_seconds or 0)
        if extend < 0:
            raise ValidationError("extend_ttl_seconds 不能为负数",
                                  tenant_id=tenant_id)
        if not add_scopes and extend <= 0:
            raise ConsentAmendmentNoChangeError(
                "变更至少需要追加作用域或延长有效期（extend_ttl_seconds > 0）",
                tenant_id=tenant_id,
            )
        return add_scopes, extend

    def request_amendment(self, tenant_id, consent_id, *,
                          add_scopes=None, extend_ttl_seconds: float = 0) -> dict:
        """合作方申请变更：待生效期间原 scopes/expires_at 不变。"""
        add_scopes, extend = self._validate_amendment(
            add_scopes, extend_ttl_seconds, tenant_id
        )
        now = self._clock()

        def _tx(consents, audit):
            return self.request_amendment_locked(
                consents, audit, tenant_id, consent_id, add_scopes, extend, now
            )

        try:
            return self._store.atomic(["consents", "audit"], _tx)
        except ConsentAmendmentInvalidStateError:
            if self._audit is not None:
                self._audit.record(
                    "consent_amendment_request", tenant_id=tenant_id, result="denied",
                    detail={"consent_id": consent_id,
                            "reason": "consent_not_authorised_for_amendment"},
                )
            raise

    def approve_amendment(self, tenant_id, consent_id, amendment_id) -> dict:
        now = self._clock()

        def _tx(consents, audit):
            return self.decide_amendment_locked(
                consents, audit, tenant_id, consent_id, amendment_id, True, now
            )

        return self._store.atomic(["consents", "audit"], _tx)

    def reject_amendment(self, tenant_id, consent_id, amendment_id) -> dict:
        now = self._clock()

        def _tx(consents, audit):
            return self.decide_amendment_locked(
                consents, audit, tenant_id, consent_id, amendment_id, False, now
            )

        return self._store.atomic(["consents", "audit"], _tx)

    def list_amendments(self, tenant_id, consent_id) -> list[dict]:
        rec = self.get(tenant_id, consent_id)
        return list(rec.get("amendments", []))

    # ---- 查询与访问闸门 --------------------------------------------------

    def get(self, tenant_id, consent_id) -> dict:
        rec = self._store.collection("consents").get(consent_id)
        if rec is None or rec["tenant_id"] != tenant_id:
            raise ConsentNotFoundError(f"同意 {consent_id!r} 不存在",
                                       tenant_id=tenant_id)
        return rec

    def check_access(self, tenant_id, consent_id, resource, scope) -> dict:
        """资源访问前的同意闸门。撤销/到期/资源不符/作用域不足分别给出不同错误码。"""
        rec = self.get(tenant_id, consent_id)
        status = ConsentStatus(rec["status"])

        def _deny(err, reason: str):
            if self._audit is not None:
                self._audit.record(
                    "consent_access",
                    tenant_id=tenant_id,
                    result="denied",
                    detail={"consent_id": consent_id, "resource": resource,
                            "scope": scope, "reason": reason},
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
            # 兜底：即使扫描器尚未运行，到期后也绝不放行（同时作废待生效变更）
            self._transition(tenant_id, consent_id,
                             ConsentStatus.EXPIRED, "consent_expire")
            _deny(ConsentExpiredError, "consent_expired")
        return rec
