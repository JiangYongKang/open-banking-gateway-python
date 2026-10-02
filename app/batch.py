"""同意动作批量提交 + 请求级幂等。

原子性与幂等约定：
* 整批（占位 + 全部动作 + 幂等结果记录 + 回调登记）在 **同一个跨集合事务**
  （``store.atomic`` 两阶段提交）内完成：要么整批全部生效，要么一个动作都不生效，
  不存在“业务已经改了、批次记录还停在处理中”的中间状态。底层存储在收尾阶段写入
  失败时，正式文件一个都不会被替换，同 request_id 重试即为全新的首次执行。
* 事务内逐项执行，每项跑在自己的快照副本上：单项失败只丢弃该项的业务改动
  （其拒绝类审计仍保留），不影响其它项，不留半成品；全部成功项与幂等记录一起提交。
* 回调按事务性 outbox 处理：事件记录在大事务内登记（pending），**事务提交成功之后**
  才做首次投递；因此回滚不发回调，提交即必有回调（失败按既有退避重试）。
  event_id 确定性派生，重放永远不会走到登记/投递这一步。
* request_id 由合作方生成，按“租户 + request_id”作用域：重复提交只执行一次，
  之后始终返回首次的完整结果（不重复扣额度/发回调/改状态）。
* 同 request_id 但动作内容不同 -> ``idempotency_conflict``。
* 并发提交同一 request_id：进程内每键锁串行；跨进程由大事务上的 flock 串行。
  落败方在锁释放后看到的必是 completed 记录，直接拿到首次结果，不会收到
  “处理中/冲突”一类中间态报错。
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import threading
import time

from .audit import make_entry
from .errors import (
    GatewayError,
    IdempotencyConflictError,
    ValidationError,
)
from .models import ConsentStatus
from .storage import _CollectionProxy

ALLOWED_ACTIONS = (
    "create", "authorise", "revoke", "amend_request", "amend_approve",
)

# 整批大事务涉及的全部集合（atomic 会内部排序加锁，这里固定声明避免遗漏）
BATCH_COLLECTIONS = ["amendments", "audit", "callbacks", "consents", "idempotency"]


def _canonical(actions: list[dict]) -> str:
    """对动作列表做规范化 JSON（键排序），用于幂等指纹。"""
    return json.dumps(actions, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _fingerprint(actions: list[dict]) -> str:
    return hashlib.sha256(_canonical(actions).encode("utf-8")).hexdigest()


class BatchService:
    def __init__(self, store, consents, amendments, audit=None, callbacks=None,
                 *, clock=time.time) -> None:
        self._store = store
        self._consents = consents
        self._amendments = amendments
        self._audit = audit
        self._callbacks = callbacks
        self._clock = clock
        self._key_locks: dict[str, threading.Lock] = {}
        self._key_locks_guard = threading.Lock()

    def _lock_for(self, key: str) -> threading.Lock:
        """同 request_id 进程内串行：并发同单第二个线程等首个完成后读既有结果。"""
        with self._key_locks_guard:
            lock = self._key_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._key_locks[key] = lock
            return lock

    def replay_result(self, tenant_id: str, request_id: str,
                      fingerprint: str) -> dict | None:
        """只读预判：若该 request_id 已完成则返回既有结果，否则 None。

        用于让幂等重放完全绕开限流配额（不重复扣额度）。
        """
        rec = self._store.collection("idempotency").get(f"{tenant_id}|{request_id}")
        if rec is None or rec["status"] != "completed":
            return None
        if rec["fingerprint"] != fingerprint:
            raise IdempotencyConflictError(
                "request_id 已被用于其它请求内容", tenant_id=tenant_id
            )
        return self._replay_payload(request_id, fingerprint, rec["results"])

    @staticmethod
    def _replay_payload(request_id: str, fingerprint: str, results: list) -> dict:
        return {"request_id": request_id, "replayed": True,
                "fingerprint": fingerprint, "results": results}

    # ---- 单项执行（每项独立快照 try，异常转结构化结果，不留半状态）---------

    def _execute_one(self, tenant_id: str, index: int, action: dict, p) -> dict:
        """在私有快照代理上执行单项。p 是各集合的 _CollectionProxy 映射。

        成功返回结果 dict（回调计划已写入 p['callbacks']）；
        失败返回结构化错误，其业务改动不会被合并回主快照。
        """
        kind = action.get("action")
        now = self._clock()
        try:
            if not isinstance(kind, str):
                raise ValidationError("action 必须是字符串")
            if kind not in ALLOWED_ACTIONS:
                raise ValidationError(
                    f"不支持的动作 {kind!r}，允许: {', '.join(ALLOWED_ACTIONS)}"
                )

            if kind == "create":
                resource = action.get("resource")
                scopes = action.get("scopes")
                ttl = action.get("ttl_seconds")
                if not isinstance(scopes, list) or not scopes:
                    raise ValidationError("create 需要非空 scopes 列表")
                if ttl is None:
                    raise ValidationError("create 需要 ttl_seconds")
                rec = self._consents.create_in_tx(
                    p["consents"], p["audit"], tenant_id, resource, scopes,
                    float(ttl), now=now,
                )
                return {"index": index, "action": kind, "ok": True,
                        "consent_id": rec["consent_id"], "result": rec}

            consent_id = action.get("consent_id")
            if not consent_id:
                raise ValidationError(f"{kind} 需要 consent_id")

            if kind == "authorise":
                rec = self._consents._transition_in_tx(
                    p["consents"], p["audit"], p["amendments"],
                    tenant_id, consent_id, ConsentStatus.AUTHORISED,
                    "consent_authorise", now,
                )
                self._plan_callback(
                    p, tenant_id, f"evt-consent-{consent_id}",
                    "consent.authorised",
                    {"consent_id": consent_id, "resource": rec["resource"]},
                    now=now,
                )
                return {"index": index, "action": kind, "ok": True,
                        "consent_id": consent_id, "result": rec}

            if kind == "revoke":
                rec = self._consents._transition_in_tx(
                    p["consents"], p["audit"], p["amendments"],
                    tenant_id, consent_id, ConsentStatus.REVOKED,
                    "consent_revoke", now,
                )
                self._plan_callback(
                    p, tenant_id, f"evt-consent-{consent_id}",
                    "consent.revoked", {"consent_id": consent_id}, now=now,
                )
                return {"index": index, "action": kind, "ok": True,
                        "consent_id": consent_id, "result": rec}

            if kind == "amend_request":
                rec = self._amendments.request_in_tx(
                    p["consents"], p["amendments"], p["audit"],
                    tenant_id, consent_id,
                    add_scopes=action.get("add_scopes"),
                    extend_seconds=action.get("extend_seconds"),
                    now=now,
                )
                return {"index": index, "action": kind, "ok": True,
                        "consent_id": consent_id,
                        "amendment_id": rec["amendment_id"], "result": rec}

            # amend_approve
            amendment_id = action.get("amendment_id")
            if not amendment_id:
                raise ValidationError("amend_approve 需要 amendment_id")
            rec = self._amendments._approve_in_tx(
                p["consents"], p["amendments"], p["audit"],
                tenant_id, amendment_id, now,
            )
            self._plan_callback(
                p, tenant_id, f"evt-amendment-{amendment_id}",
                "consent.amendment_approved",
                {"consent_id": consent_id, "amendment_id": amendment_id},
                now=now,
            )
            return {"index": index, "action": kind, "ok": True,
                    "consent_id": consent_id, "amendment_id": amendment_id,
                    "result": rec}
        except GatewayError as exc:
            return {"index": index, "action": kind if isinstance(kind, str) else None,
                    "ok": False, "error": {"code": exc.code, "message": exc.message}}
        except Exception as exc:  # noqa: BLE001 防御：单项任何意外都不外溢，批继续
            return {"index": index, "action": kind if isinstance(kind, str) else None,
                    "ok": False,
                    "error": {"code": "internal_error", "message": str(exc)}}

    def _plan_callback(self, p, tenant_id, event_id, event_type, payload, *, now) -> None:
        """事务内登记回调 outbox（无 dispatcher 时跳过，等价于未启用回调）。"""
        if self._callbacks is None:
            return
        out = self._callbacks.plan_in_tx(
            p["callbacks"], p["audit"], event_id, tenant_id, event_type, payload, now=now
        )
        if not out["duplicate"]:
            p["_new_events"].append(event_id)

    def _validate(self, actions) -> None:
        if not isinstance(actions, list) or not actions:
            raise ValidationError("actions 必须是非空列表")
        if len(actions) > 100:
            raise ValidationError("单批最多 100 个动作")
        for i, a in enumerate(actions):
            if not isinstance(a, dict):
                raise ValidationError(f"第 {i} 项必须是对象")

    # ---- 公开 API --------------------------------------------------------

    @staticmethod
    def fingerprint(actions: list[dict]) -> str:
        """动作列表的幂等指纹（规范化 JSON 的 SHA-256）。"""
        return _fingerprint(actions)

    def submit(self, tenant_id: str, request_id: str, actions: list[dict]) -> dict:
        if not request_id or not isinstance(request_id, str):
            raise ValidationError("request_id 不能为空")
        self._validate(actions)
        fingerprint = _fingerprint(actions)
        idem_key = f"{tenant_id}|{request_id}"

        # 进程内同 request_id 串行；跨进程由下方大事务上的 flock 串行。
        with self._lock_for(idem_key):
            # atomic 按集合名排序后按 BATCH_COLLECTIONS 的声明顺序传入同名代理：
            # amendments, audit, callbacks, consents, idempotency
            def _tx(amendments, audit, callbacks, consents, idem):
                return self._run_transaction(
                    idem_key, tenant_id, request_id, fingerprint, actions,
                    {"idempotency": idem, "consents": consents,
                     "amendments": amendments, "audit": audit,
                     "callbacks": callbacks},
                )

            outcome = self._store.atomic(BATCH_COLLECTIONS, _tx)
            if outcome["kind"] == "replay":
                return self._replay_payload(
                    request_id, fingerprint, outcome["results"]
                )
            # 事务已提交：投递本批新登记的回调（outbox）。投递失败不影响批次结果，
            # 事件保持 pending 并由既有退避重试机制兜底。
            if self._callbacks is not None and outcome["events"]:
                self._callbacks.deliver_pending(outcome["events"])
            return {"request_id": request_id, "replayed": False,
                    "fingerprint": fingerprint,
                    "summary": outcome["summary"],
                    "results": outcome["results"]}

    def _run_transaction(self, idem_key, tenant_id, request_id, fingerprint,
                         actions, base) -> dict:
        """大事务体：查重 -> 逐项在私有快照执行 -> 合并 -> 写定幂等结果。

        任一未捕获异常（含落盘序列化失败，发生在 fn 返回后的两阶段提交阶段）
        都会让整批不落任何文件。
        """
        existing = base["idempotency"].get(idem_key)
        if existing is not None and existing.get("status") == "completed":
            if existing["fingerprint"] != fingerprint:
                raise IdempotencyConflictError(
                    "request_id 已被用于其它请求内容", tenant_id=tenant_id
                )
            # 并发落败方（无论同进程还是跨进程）走到这里时，首个事务必然已经
            # 完整提交：processing 状态从不持久化，因此这里只可能是 completed。
            return {"kind": "replay", "results": existing["results"]}
        # 非 completed 记录只可能来自旧版本遗留的卡死占位（新代码从不持久化
        # processing）：它从未成功落定，本线程直接接管并以本次结果覆盖，
        # 保证卡住的 request_id 重试即可恢复。
        if existing is not None:
            logging.getLogger("obg.batch").warning(
                "request_id=%s 存在非 completed 残留记录(status=%s)，接管重跑",
                idem_key, existing.get("status"),
            )

        created_at = self._clock()
        # 主工作快照（即事务代理背后的 dict）；每项在自己的深拷贝副本上执行，
        # 成功才整体替换，失败只把该项产生的拒绝类审计合并回来。
        working = {name: base[name].snapshot()
                   for name in ("consents", "amendments", "callbacks")}
        audit_snapshot = base["audit"].snapshot()
        results: list[dict] = []
        new_events: list[str] = []

        for i, action in enumerate(actions):
            private = {
                name: _CollectionProxy(name, copy.deepcopy(working[name]))
                for name in ("consents", "amendments", "callbacks")
            }
            # 审计只增不读：每项从空代理起步，执行后无论成败都合并回主审计，
            # 这样失败项的 denied 审计得以保留，又不必深拷贝整个审计集合。
            private_audit = _CollectionProxy("audit", {})
            private["audit"] = private_audit
            private["_new_events"] = []
            result = self._execute_one(tenant_id, i, action, private)
            audit_snapshot.update(private_audit.snapshot())
            if result["ok"]:
                for name in ("consents", "amendments", "callbacks"):
                    working[name] = private[name].snapshot()
                new_events.extend(private["_new_events"])
            results.append(result)

        # 把最终快照写回事务代理（atomic 将统一序列化、两阶段提交）
        for name in ("consents", "amendments", "callbacks"):
            base[name]._data.clear()
            base[name]._data.update(working[name])
        base["audit"]._data.clear()
        base["audit"]._data.update(audit_snapshot)

        summary = {
            "total": len(results),
            "succeeded": sum(1 for r in results if r["ok"]),
            "failed": sum(1 for r in results if not r["ok"]),
        }
        base["idempotency"].put(idem_key, {
            "tenant_id": tenant_id,
            "request_id": request_id,
            "fingerprint": fingerprint,
            "status": "completed",
            "created_at": created_at,
            "finished_at": self._clock(),
            "results": results,
            "summary": summary,
        })
        if self._audit is not None:
            eid, entry = make_entry(
                "consent_batch_submit",
                tenant_id=tenant_id,
                result="state_change",
                detail={"request_id": request_id, "fingerprint": fingerprint[:16],
                        **summary},
                clock=self._clock,
            )
            base["audit"].put(eid, entry)
        return {"kind": "completed", "results": results, "summary": summary,
                "events": new_events}
