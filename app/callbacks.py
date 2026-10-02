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

    def trigger(
        self,
        event_id: str,
        tenant_id: str,
        event_type: str,
        payload: dict,
    ) -> dict:
        """幂等触发：首次立即投递一次；重复 event_id 直接返回既有记录。"""
        import json

        if len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) > self._max_payload_bytes:
            raise CallbackPayloadTooLargeError(
                f"回调载荷超过 {self._max_payload_bytes} 字节", tenant_id=tenant_id
            )

        def _tx(callbacks, audit):
            existing = callbacks.get(event_id)
            if existing is not None:
                return {"record": existing, "duplicate": True}
            now = self._clock()
            record = {
                "event_id": event_id,
                "tenant_id": tenant_id,
                "event_type": event_type,
                "payload": payload,
                "status": "pending",
                "attempts": 0,
                "max_attempts": self._max_attempts,
                "created_at": now,
                "updated_at": now,
                "next_attempt_at": now,
                "delivered_at": None,
                "last_error": None,
                "attempt_log": [],
            }
            callbacks.put(event_id, record)
            if self._audit is not None:
                eid, entry = make_entry(
                    "callback_trigger",
                    tenant_id=tenant_id,
                    result="state_change",
                    detail={"event_id": event_id, "event_type": event_type},
                    clock=self._clock,
                )
                audit.put(eid, entry)
            return {"record": record, "duplicate": False}

        result = self._store.atomic(["callbacks", "audit"], _tx)
        if result["duplicate"]:
            return result["record"]
        # 首次立即尝试投递（投递结果单独事务写回）
        self._attempt_one(event_id, sleep_before=False)
        return self.status(event_id)

    def queue_in_tx(
        self,
        event_id: str,
        tenant_id: str,
        event_type: str,
        payload: dict,
        callbacks_proxy,
        audit_proxy=None,
    ) -> tuple[dict, bool]:
        """在调用方的事务代理内幂等登记回调事件，**不**实际投递。

        用于批量提交的 outbox：事件与业务状态在同一个大事务里落定（事务提交前
        一条回调都不发，事务失败则事件与业务一起回滚）。返回
        ``(record, created)``，``created=False`` 表示该 event_id 此前已存在，
        调用方不应再为其触发首次投递（其投递生命周期已经存在）。
        """
        import json

        if len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) > self._max_payload_bytes:
            raise CallbackPayloadTooLargeError(
                f"回调载荷超过 {self._max_payload_bytes} 字节", tenant_id=tenant_id
            )
        existing = callbacks_proxy.get(event_id)
        if existing is not None:
            return existing, False
        now = self._clock()
        record = {
            "event_id": event_id,
            "tenant_id": tenant_id,
            "event_type": event_type,
            "payload": payload,
            "status": "pending",
            "attempts": 0,
            "max_attempts": self._max_attempts,
            "created_at": now,
            "updated_at": now,
            "next_attempt_at": now,
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
        return record, True

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
