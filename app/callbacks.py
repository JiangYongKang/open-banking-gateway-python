"""回调事件投递：幂等触发、指数退避重试、最终失败可查询。

关键保证：
* ``trigger`` 以 event_id 幂等：重复触发同一事件返回既有记录，不产生第二次投递；
* 投递状态机 PENDING -> DELIVERED / FAILED（attempts 达上限），DELIVERED 与
  FAILED 都是终态；
* 每次尝试独立记录 attempt 日志，失败按 base * factor**(n-1) 退避，
  下一次最早投递时间 next_attempt_at 可查询；
* 事件之间各用各的记录，重试/失败互不污染。
"""
from __future__ import annotations

import time

from .audit import make_entry
from .errors import CallbackPayloadTooLargeError


def default_sender(record: dict) -> None:
    """默认投递器：什么也不做即视为成功（本地无外部服务）。

    测试时可注入会失败/抛异常的 sender 模拟第三方回调端点。
    """
    return None


class CallbackDispatcher:
    def __init__(
        self,
        store,
        audit=None,
        *,
        sender=default_sender,
        clock=time.time,
        sleep=None,
        max_payload_bytes: int = 64 * 1024,
        max_attempts: int = 5,
        backoff_base: float = 0.01,
        backoff_factor: float = 2.0,
    ) -> None:
        self._store = store
        self._coll = store.collection("callbacks")
        self._audit = audit
        self._sender = sender
        self._clock = clock
        self._sleep = sleep or (lambda _: None)
        self._max_payload_bytes = max_payload_bytes
        self._max_attempts = max_attempts
        self._base = backoff_base
        self._factor = backoff_factor

    def _backoff(self, failed_attempts: int) -> float:
        return self._base * (self._factor ** max(0, failed_attempts - 1))

    # ---- 事务内 outbox 原语（供批量大事务调用）---------------------------

    def plan_in_tx(self, callbacks_proxy, audit_proxy, event_id: str, tenant_id: str,
                   event_type: str, payload: dict, *, now: float | None = None) -> dict:
        """在调用方事务内登记一个 pending 回调（含触发审计），但不投递。

        * 按 event_id 幂等：已存在（无论什么状态）则原样返回，不重复登记；
        * 投递发生在外层事务提交之后（:meth:`deliver_pending`），
          因此事务整体回滚时绝不会发出回调，而提交成功后回调绝不会丢；
        * 返回 ``{"record": ..., "duplicate": bool}``，duplicate 为 True 时
          调用方不应再安排投递。
        """
        import json

        if len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) > self._max_payload_bytes:
            raise CallbackPayloadTooLargeError(
                f"回调载荷超过 {self._max_payload_bytes} 字节", tenant_id=tenant_id
            )
        existing = callbacks_proxy.get(event_id)
        if existing is not None:
            return {"record": existing, "duplicate": True}
        ts = self._clock() if now is None else now
        record = {
            "event_id": event_id,
            "tenant_id": tenant_id,
            "event_type": event_type,
            "payload": payload,
            "status": "pending",
            "attempts": 0,
            "max_attempts": self._max_attempts,
            "created_at": ts,
            "updated_at": ts,
            "next_attempt_at": ts,
            "delivered_at": None,
            "last_error": None,
            "attempt_log": [],
        }
        callbacks_proxy.put(event_id, record)
        if self._audit is not None and audit_proxy is not None:
            eid, entry = make_entry(
                "callback_trigger",
                tenant_id=tenant_id,
                result="state_change",
                detail={"event_id": event_id, "event_type": event_type},
                clock=self._clock,
            )
            audit_proxy.put(eid, entry)
        return {"record": record, "duplicate": False}

    def deliver_pending(self, event_ids) -> list[dict]:
        """事务提交后调用：对新登记的事件做首次投递，已投递/已存在的自动跳过。"""
        statuses = []
        for event_id in dict.fromkeys(event_ids):
            statuses.append(self._attempt_one(event_id, sleep_before=False))
        return statuses

    def trigger(
        self,
        event_id: str,
        tenant_id: str,
        event_type: str,
        payload: dict,
    ) -> dict:
        """幂等触发：首次立即投递一次；重复 event_id 直接返回既有记录。"""

        def _tx(callbacks, audit):
            return self.plan_in_tx(
                callbacks, audit, event_id, tenant_id, event_type, payload
            )

        result = self._store.atomic(["callbacks", "audit"], _tx)
        if result["duplicate"]:
            return result["record"]
        # 首次立即尝试投递（投递结果单独事务写回）
        self._attempt_one(event_id, sleep_before=False)
        return self.status(event_id)

    def _attempt_one(self, event_id: str, *, sleep_before: bool) -> dict | None:
        """对单个事件执行一次投递尝试并原子更新记录；不满足条件则跳过返回快照。"""
        # 1) 锁内做最后一次可投递判定（状态/到点时间/已尝试次数），取出快照
        plan = {}

        def _check(data: dict):
            rec = data.get(event_id)
            if rec is None or rec["status"] != "pending":
                plan["skip"] = rec
                return None
            now = self._clock()
            if now < rec["next_attempt_at"]:
                plan["wait"] = rec
                return None
            plan["attempt_no"] = rec["attempts"] + 1
            plan["snapshot"] = dict(rec)

        self._coll.modify(_check)
        if "skip" in plan:
            return plan["skip"]
        if "wait" in plan:
            return plan["wait"]

        snapshot = plan["snapshot"]
        attempt_no = plan["attempt_no"]
        if sleep_before and attempt_no > 1:
            self._sleep(max(0.0, snapshot["next_attempt_at"] - self._clock()))

        # 2) 锁外执行实际投递（模拟 HTTP 调用），不持锁、不阻塞其它事件
        try:
            self._sender(snapshot)
            ok, error = True, None
        except Exception as exc:  # 投递方任何异常都视为可重试失败
            ok, error = False, f"{type(exc).__name__}: {exc}"

        # 3) 事务内条件更新：仅当记录仍是 pending 且尝试序号未变才落盘，
        #    杜绝与并发/重复尝试交叉污染。
        def _tx(callbacks, audit) -> None:
            rec = callbacks.get(event_id)
            if rec is None or rec["status"] != "pending":
                return
            if rec["attempts"] != attempt_no - 1:
                return
            ts = self._clock()
            rec["attempts"] = attempt_no
            rec["updated_at"] = ts
            rec["attempt_log"].append(
                {"attempt": attempt_no, "ts": ts,
                 "result": "success" if ok else "failed", "error": error}
            )
            if ok:
                rec["status"] = "delivered"
                rec["delivered_at"] = ts
                rec["next_attempt_at"] = None
                rec["last_error"] = None
            elif rec["attempts"] >= rec["max_attempts"]:
                rec["status"] = "failed"
                rec["next_attempt_at"] = None
                rec["last_error"] = error
            else:
                rec["last_error"] = error
                rec["next_attempt_at"] = ts + self._backoff(attempt_no)
            if self._audit is not None:
                eid, entry = make_entry(
                    "callback_attempt",
                    tenant_id=rec["tenant_id"],
                    result=("state_change" if rec["status"] == "delivered"
                            else "error" if rec["status"] == "failed" else "denied"),
                    detail={"event_id": event_id, "attempt": attempt_no,
                            "delivery_result": "success" if ok else "failed",
                            "new_status": rec["status"], "error": error},
                    clock=self._clock,
                )
                audit.put(eid, entry)

        self._store.atomic(["callbacks", "audit"], _tx)
        return self.status(event_id)

    def recover_undelivered(self, now: float | None = None, *, grace_seconds: float = 2.0) -> int:
        """补投事务性 outbox 中“已登记但从未投递过”的事件。

        批量大事务提交成功后、首次投递前进程崩溃时，回调记录停在 pending 且
        attempts == 0（``run_due_retries`` 只重试投递过至少一次的事件，不会覆盖
        这种情况）。仅捞 created_at 早于宽限期的事件，避免与正在进行的首次投递
        并发（实际投递仍由 _attempt_one 的乐观条件保护，不会重复计数）。
        返回本次补投的事件数。
        """
        current = self._clock() if now is None else now
        stale = [
            rec["event_id"]
            for rec in self._coll.list_items()
            if rec["status"] == "pending"
            and rec["attempts"] == 0
            and rec["created_at"] <= current - grace_seconds
        ]
        for event_id in stale:
            self._attempt_one(event_id, sleep_before=False)
        return len(stale)

    def run_due_retries(self, now: float | None = None) -> int:
        """重试所有到点且仍 pending 的事件，返回本次尝试的事件数。"""
        current = self._clock() if now is None else now
        due = [
            rec["event_id"]
            for rec in self._coll.list_items()
            if rec["status"] == "pending"
            and rec["attempts"] > 0
            and rec["next_attempt_at"] is not None
            and rec["next_attempt_at"] <= current
        ]
        for event_id in due:
            self._attempt_one(event_id, sleep_before=True)
        return len(due)

    def status(self, event_id: str) -> dict:
        rec = self._coll.get(event_id)
        if rec is None:
            from .errors import CallbackNotFoundError

            raise CallbackNotFoundError(f"回调事件 {event_id!r} 不存在")
        return rec
