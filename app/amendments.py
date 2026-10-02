"""同意变更（amendment）服务：追加作用域 / 延长有效期。

不变量：
* 变更在批准前不影响生效中的 scopes / expires_at，业务访问继续走旧版本；
* 批准在单一跨集合事务内完成（consents + amendments + audit），
  旧版本完整快照写入 consent 的 versions 链，所有 history 只增不改；
* 同意在变更待生效期间被撤销/到期时，变更单一并作废（void），
  作废后批准显式失败，新作用域/有效期永不可用；
* 待生效中的同意，访问闸门只按当前生效版本放行（request/approve 不改中间可见值）。
"""
from __future__ import annotations

import time
import uuid

from .audit import make_entry
from .errors import (
    ConsentAmendmentConflictError,
    ConsentAmendmentNotFoundError,
    ConsentAmendmentVoidError,
    ConsentNotFoundError,
    ValidationError,
)
from .models import AmendmentStatus, ConsentStatus

# 同意进入终态 -> 待生效变更的作废原因
VOID_REASON_BY_STATUS = {
    ConsentStatus.REVOKED.value: "consent_revoked",
    ConsentStatus.EXPIRED.value: "consent_expired",
}


def _new_amendment_id() -> str:
    return "amend-" + uuid.uuid4().hex[:16]


class AmendmentService:
    def __init__(self, store, audit=None, consents=None, *, clock=time.time) -> None:
        self._store = store
        self._audit = audit
        self._consents = consents
        self._clock = clock

    # ---- 查询 ------------------------------------------------------------

    def get(self, tenant_id: str, amendment_id: str) -> dict:
        rec = self._store.collection("amendments").get(amendment_id)
        if rec is None or rec["tenant_id"] != tenant_id:
            raise ConsentAmendmentNotFoundError(
                f"变更单 {amendment_id!r} 不存在", tenant_id=tenant_id
            )
        return rec

    def _find_pending(self, amendments_proxy, consent_id: str) -> dict | None:
        for rec in amendments_proxy.items():
            if rec["consent_id"] == consent_id and rec["status"] == AmendmentStatus.PENDING.value:
                return rec
        return None

    # ---- 事务内原语：操作的是事务代理快照，落盘由外层 store.atomic 统一完成

    def request_in_tx(
        self,
        consents_proxy,
        amendments_proxy,
        audit_proxy,
        tenant_id: str,
        consent_id: str,
        *,
        add_scopes: list[str] | None = None,
        extend_seconds: float | None = None,
        now: float | None = None,
    ) -> dict:
        """在调用方事务内完成变更申请的全部校验、快照计算与写入。"""
        add_scopes = list(add_scopes or [])
        if any(not isinstance(s, str) or not s for s in add_scopes):
            raise ValidationError("add_scopes 必须是非空字符串列表", tenant_id=tenant_id)
        if extend_seconds is not None and (
            not isinstance(extend_seconds, (int, float)) or extend_seconds <= 0
        ):
            raise ValidationError("extend_seconds 必须为正数", tenant_id=tenant_id)
        if not add_scopes and not extend_seconds:
            raise ValidationError(
                "变更至少包含 add_scopes 或 extend_seconds 之一", tenant_id=tenant_id
            )
        extend_seconds = float(extend_seconds) if extend_seconds else 0.0
        ts = self._clock() if now is None else now

        rec = consents_proxy.get(consent_id)
        if rec is None or rec["tenant_id"] != tenant_id:
            raise ConsentNotFoundError(
                f"同意 {consent_id!r} 不存在", tenant_id=tenant_id
            )
        status = ConsentStatus(rec["status"])
        if status is not ConsentStatus.AUTHORISED:
            raise ConsentAmendmentConflictError(
                f"同意当前状态为 {status.value}，只有生效中的同意可以申请变更",
                tenant_id=tenant_id,
            )
        if self._find_pending(amendments_proxy, consent_id) is not None:
            raise ConsentAmendmentConflictError(
                "该同意已有待生效的变更，请先批准或等待其作废",
                tenant_id=tenant_id,
            )

        # 申请时刻的目标值快照：并集去重（保持顺序），有效期在“当前到期点”上延长
        merged = list(rec["scopes"])
        for s in add_scopes:
            if s not in merged:
                merged.append(s)
        current_expires = rec["expires_at"]
        target_expires = (
            current_expires + extend_seconds if extend_seconds else current_expires
        )
        if merged == list(rec["scopes"]) and not extend_seconds:
            raise ConsentAmendmentConflictError(
                "变更没有任何实际改动（作用域均已包含且未申请延期）",
                tenant_id=tenant_id,
            )

        amendment = {
            "amendment_id": _new_amendment_id(),
            "tenant_id": tenant_id,
            "consent_id": consent_id,
            "status": AmendmentStatus.PENDING.value,
            "add_scopes": add_scopes,
            "extend_seconds": extend_seconds,
            "base_scopes": list(rec["scopes"]),
            "base_expires_at": current_expires,
            "result_scopes": merged,
            "result_expires_at": target_expires,
            "base_version": rec["version"],
            "created_at": ts,
            "decided_at": None,
            "void_reason": None,
            "history": [{
                "ts": ts, "action": "amend_request",
                "from": None, "to": AmendmentStatus.PENDING.value,
            }],
        }
        return self._request_put_in_tx(
            consents_proxy, amendments_proxy, audit_proxy, tenant_id, amendment
        )

    def _request_put_in_tx(self, consents_proxy, amendments_proxy, audit_proxy,
                           tenant_id: str, amendment: dict) -> dict:
        """在调用方事务内写入一个已完成全部校验/快照计算的变更申请。"""
        amendment_id = amendment["amendment_id"]
        amendments_proxy.put(amendment_id, amendment)
        if audit_proxy is not None:
            eid, entry = make_entry(
                "consent_amendment_request",
                tenant_id=tenant_id,
                result="state_change",
                detail={"consent_id": amendment["consent_id"],
                        "amendment_id": amendment_id,
                        "add_scopes": amendment["add_scopes"],
                        "extend_seconds": amendment["extend_seconds"],
                        "base_version": amendment["base_version"]},
                clock=self._clock,
            )
            audit_proxy.put(eid, entry)
        return amendment

    def _approve_in_tx(self, consents_proxy, amendments_proxy, audit_proxy,
                       tenant_id: str, amendment_id: str, now: float) -> dict:
        """在调用方事务内批准变更；已作废显式拒绝；重复批准幂等返回。"""
        amendment = amendments_proxy.get(amendment_id)
        if amendment is None or amendment["tenant_id"] != tenant_id:
            raise ConsentAmendmentNotFoundError(
                f"变更单 {amendment_id!r} 不存在", tenant_id=tenant_id
            )
        am_status = AmendmentStatus(amendment["status"])
        if am_status is AmendmentStatus.VOID:
            raise ConsentAmendmentVoidError(
                f"变更已作废（{amendment.get('void_reason')}），不能批准",
                tenant_id=tenant_id,
            )
        if am_status is AmendmentStatus.APPROVED:
            # 重复批准：幂等返回当前同意，不再改任何状态
            return consents_proxy.get(amendment["consent_id"])

        consent_id = amendment["consent_id"]
        rec = consents_proxy.get(consent_id)
        if rec is None or rec["tenant_id"] != tenant_id:
            raise ConsentNotFoundError(
                f"同意 {consent_id!r} 不存在", tenant_id=tenant_id
            )
        if ConsentStatus(rec["status"]) is not ConsentStatus.AUTHORISED:
            # 防御：终态化钩子理论上已把变更作废，这里在同事务内补作废并拒绝
            self._void_in_tx(
                amendments_proxy, audit_proxy, amendment,
                VOID_REASON_BY_STATUS.get(rec["status"], "consent_finalized"), now,
            )
            raise ConsentAmendmentVoidError(
                "同意已不在生效状态，变更随之作废", tenant_id=tenant_id
            )

        # 1) 旧版本完整快照入版本链（只增不改，旧版本永不丢失）
        versions = rec.setdefault("versions", [])
        versions.append({
            "version": rec["version"],
            "scopes": list(rec["scopes"]),
            "expires_at": rec["expires_at"],
            "ttl_seconds": rec.get("ttl_seconds"),
            "replaced_at": now,
            "replaced_by_amendment": amendment_id,
        })
        # 2) 新版本生效：仅在批准后改变对外可见值
        old_scopes, old_expires = list(rec["scopes"]), rec["expires_at"]
        rec["scopes"] = list(amendment["result_scopes"])
        rec["expires_at"] = amendment["result_expires_at"]
        if rec.get("authorised_at") is not None:
            rec["ttl_seconds"] = amendment["result_expires_at"] - rec["authorised_at"]
        rec["version"] += 1
        rec["history"].append({
            "ts": now, "from": ConsentStatus.AUTHORISED.value,
            "to": ConsentStatus.AUTHORISED.value,
            "action": "amendment_approved",
            "amendment_id": amendment_id,
        })
        # 3) 变更单落定
        amendment["status"] = AmendmentStatus.APPROVED.value
        amendment["decided_at"] = now
        amendment["history"].append({
            "ts": now, "action": "amend_approve",
            "from": AmendmentStatus.PENDING.value,
            "to": AmendmentStatus.APPROVED.value,
            "detail": {"consent_version": rec["version"]},
        })
        consents_proxy.put(consent_id, rec)
        amendments_proxy.put(amendment_id, amendment)
        if audit_proxy is not None:
            eid, entry = make_entry(
                "consent_amendment_approved",
                tenant_id=tenant_id,
                result="state_change",
                detail={"consent_id": consent_id, "amendment_id": amendment_id,
                        "version": rec["version"],
                        "old_scopes": old_scopes, "new_scopes": list(rec["scopes"]),
                        "old_expires_at": old_expires,
                        "new_expires_at": rec["expires_at"]},
                clock=self._clock,
            )
            audit_proxy.put(eid, entry)
        return rec

    # ---- 申请 ------------------------------------------------------------

    def request(
        self,
        tenant_id: str,
        consent_id: str,
        *,
        add_scopes: list[str] | None = None,
        extend_seconds: float | None = None,
    ) -> dict:
        """申请变更；仅 AUTHORISED 同意可申请，同一同意同时只允许一个待生效变更。"""

        def _tx(consents, amendments, audit):
            return self.request_in_tx(
                consents, amendments, audit, tenant_id, consent_id,
                add_scopes=add_scopes, extend_seconds=extend_seconds,
            )

        return self._store.atomic(["consents", "amendments", "audit"], _tx)

    # ---- 批准 ------------------------------------------------------------

    def approve(self, tenant_id: str, amendment_id: str) -> dict:
        """批准变更并原子生效；已作废的变更显式拒绝；重复批准幂等返回。"""
        now = self._clock()

        def _tx(consents, amendments, audit):
            return self._approve_in_tx(
                consents, amendments, audit, tenant_id, amendment_id, now
            )

        return self._store.atomic(["consents", "amendments", "audit"], _tx)

    # ---- 作废（由同意终态化在同事务内调用）--------------------------------

    @staticmethod
    def _void_in_tx(amendments_proxy, audit_proxy, amendment: dict,
                    reason: str, now: float) -> None:
        amendment["status"] = AmendmentStatus.VOID.value
        amendment["decided_at"] = now
        amendment["void_reason"] = reason
        amendment["history"].append({
            "ts": now, "action": "amend_void",
            "from": AmendmentStatus.PENDING.value,
            "to": AmendmentStatus.VOID.value,
            "detail": {"reason": reason},
        })
        amendments_proxy.put(amendment["amendment_id"], amendment)
        if audit_proxy is not None:
            eid, entry = make_entry(
                "consent_amendment_void",
                tenant_id=amendment["tenant_id"],
                result="state_change",
                detail={"consent_id": amendment["consent_id"],
                        "amendment_id": amendment["amendment_id"], "reason": reason},
                clock=lambda: now,
            )
            audit_proxy.put(eid, entry)

    def void_pending_in_tx(self, consents_proxy, amendments_proxy, audit_proxy,
                           consent_id: str, reason: str, now: float | None = None) -> list[str]:
        """在同意流转事务内作废挂在该同意上的待生效变更，返回作废的变更 id 列表。"""
        ts = self._clock() if now is None else now
        pending = [
            rec for rec in amendments_proxy.items()
            if rec["consent_id"] == consent_id
            and rec["status"] == AmendmentStatus.PENDING.value
        ]
        voided = []
        for amendment in pending:
            self._void_in_tx(
                amendments_proxy,
                audit_proxy if self._audit is not None else None,
                amendment, reason, ts,
            )
            voided.append(amendment["amendment_id"])
        return voided
