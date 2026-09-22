"""回调事件幂等投递、退避重试与可查询死信。

约定：
- trigger 幂等：相同 event_id 只建一次事件并尝试首次投递；重复触发只回显已有
  事件，绝不重复投递。“查重 + 占位 + 建事件 + 审计”在同一把存储锁内原子完成，
  并发触发只有一个胜出者会走到首次投递。
- 投递失败后 next_attempt_at = now + base * factor**(attempts-1)，状态 RETRYING；
  attempts 达到 max_attempts 仍失败则进入 DEAD（可查询的最终失败态）。
- 每个事件独立维护 attempts/attempt_history/in_flight，重试互不串状态。
- 调用方为本地 SimulatedCaller（纯内存模拟），不访问外部服务。
"""
from __future__ import annotations

import copy

from app.errors import ErrorCode, GatewayError
from app.logging_utils import get_logger
from app.models import CallbackEvent, CallbackStatus

logger = get_logger("callbacks")


class CallbackService:
    def __init__(self, storage, audit, settings, clock, caller) -> None:  # noqa: ANN001
        self.storage = storage
        self.audit = audit
        self.settings = settings
        self.clock = clock
        self.caller = caller

    # ---- 触发（幂等）--------------------------------------------------
    def trigger(self, tenant_id: str, event_id: str, callback_url: str,
                payload: dict) -> CallbackEvent:
        """原子触发：已存在则回显（不投递）；不存在则建事件并首次投递。"""
        with self.storage.lock:
            existing = self.storage.events.get(event_id)
            if existing is not None:
                logger.info("duplicate trigger ignored event=%s status=%s attempts=%d",
                            event_id, existing.status.value, existing.attempts)
                self.audit.write(tenant_id, "callback_trigger", "info",
                                 f"重复触发已幂等忽略 {event_id}",
                                 {"event_id": event_id,
                                  "status": existing.status.value})
                if existing.tenant_id != tenant_id:
                    raise GatewayError(ErrorCode.TENANT_MISMATCH,
                                       "event_id 已存在但属于其他租户")
                return copy.deepcopy(existing)

            now = self.clock.now()
            event = CallbackEvent(
                event_id=event_id, tenant_id=tenant_id, callback_url=callback_url,
                payload=dict(payload), status=CallbackStatus.PENDING,
                max_attempts=self.settings.callback_max_attempts,
                created_at=now, next_attempt_at=now)
            try:
                self.storage.events[event_id] = event
                self.audit.write(tenant_id, "callback_trigger", "state_change",
                                 f"登记回调事件 {event_id} url={callback_url}",
                                 {"event_id": event_id,
                                  "callback_url": callback_url})
            except Exception:
                # 审计失败：失败请求不残留处理状态
                self.storage.events.pop(event_id, None)
                raise
            # 首次投递在同一把锁内原子完成（模拟调用方纯内存、可重入安全）
            return self._attempt_locked(event)

    # ---- 投递与重试 ----------------------------------------------------
    def deliver_once(self, event_id: str) -> CallbackEvent:
        with self.storage.lock:
            event = self.storage.events.get(event_id)
            if event is None:
                raise GatewayError(ErrorCode.CONSENT_NOT_FOUND,
                                   f"回调事件不存在: {event_id}", status_code=404)
            if event.status == CallbackStatus.DELIVERED:
                logger.info("already delivered, skip event=%s", event_id)
                return copy.deepcopy(event)
            if event.status == CallbackStatus.DEAD:
                raise GatewayError(ErrorCode.CALLBACK_EVENT_DEAD,
                                   f"事件已进入最终失败态: {event_id}",
                                   details={"event_id": event_id,
                                            "attempts": event.attempts,
                                            "last_error": event.last_error})
            if event.in_flight:
                raise GatewayError(ErrorCode.RATE_LIMITED_REJECT,
                                   "该事件正在投递中", status_code=409)
            if event.attempts > 0 and self.clock.now() < event.next_attempt_at:
                raise GatewayError(ErrorCode.RATE_LIMITED_REJECT,
                                   "退避时间未到，暂不可重试", status_code=409,
                                   details={"retry_after_seconds":
                                            round(event.next_attempt_at
                                                  - self.clock.now(), 3)})
            return self._attempt_locked(event)

    def _attempt_locked(self, event: CallbackEvent) -> CallbackEvent:
        """调用方必须持有 storage.lock；执行一次投递并落定状态。"""
        event.in_flight = True
        try:
            ok, error = self.caller.post(event.event_id, event.callback_url,
                                         dict(event.payload))
        finally:
            event.in_flight = False

        event.attempts += 1
        record = {"attempt": event.attempts, "at": self.clock.now(),
                  "ok": ok, "error": error}
        if ok:
            event.status = CallbackStatus.DELIVERED
            event.delivered_at = self.clock.now()
            event.next_attempt_at = 0.0
            event.last_error = ""
            event.attempt_history.append({**record, "result": "delivered"})
            self.audit.write(event.tenant_id, "callback_deliver", "allowed",
                             f"回调投递成功 {event.event_id} 尝试 {event.attempts} 次",
                             {"event_id": event.event_id, "attempts": event.attempts})
            logger.info("callback delivered event=%s attempts=%d",
                        event.event_id, event.attempts)
        else:
            event.last_error = error
            if event.attempts >= event.max_attempts:
                event.status = CallbackStatus.DEAD
                event.next_attempt_at = 0.0
                event.attempt_history.append({**record, "result": "dead"})
                self.audit.write(event.tenant_id, "callback_dead", "state_change",
                                 f"回调进入死信 {event.event_id} "
                                 f"尝试 {event.attempts}/{event.max_attempts}",
                                 {"event_id": event.event_id,
                                  "attempts": event.attempts, "last_error": error})
                logger.warning("callback DEAD event=%s attempts=%d last=%s",
                               event.event_id, event.attempts, error)
            else:
                backoff = (self.settings.callback_backoff_base_seconds
                           * self.settings.callback_backoff_factor
                           ** (event.attempts - 1))
                event.status = CallbackStatus.RETRYING
                event.next_attempt_at = self.clock.now() + backoff
                event.attempt_history.append({**record, "result": "retrying",
                                              "backoff": backoff})
                self.audit.write(event.tenant_id, "callback_retry", "state_change",
                                 f"回调失败将重试 {event.event_id} "
                                 f"第 {event.attempts} 次 backoff={backoff:.3f}",
                                 {"event_id": event.event_id,
                                  "attempt": event.attempts, "error": error,
                                  "backoff_seconds": backoff})
                logger.warning("callback retry scheduled event=%s attempt=%d "
                               "backoff=%.3f", event.event_id, event.attempts, backoff)
        return copy.deepcopy(event)

    def deliver_until_settled(self, event_id: str) -> CallbackEvent:
        """按退避推进（注入时钟）直至 DELIVERED / DEAD；测试与运维使用。"""
        while True:
            with self.storage.lock:
                event = self.storage.events.get(event_id)
                if event is None:
                    raise GatewayError(ErrorCode.CONSENT_NOT_FOUND,
                                       f"回调事件不存在: {event_id}", status_code=404)
                status = event.status
                wait = max(0.0, event.next_attempt_at - self.clock.now())
            if status in (CallbackStatus.DELIVERED, CallbackStatus.DEAD):
                return self.get(event_id)
            if wait > 0:
                self.clock.advance(wait)
            self.deliver_once(event_id)

    # ---- 查询 ----------------------------------------------------------
    def get(self, event_id: str) -> CallbackEvent:
        with self.storage.lock:
            event = self.storage.events.get(event_id)
            if event is None:
                raise GatewayError(ErrorCode.CONSENT_NOT_FOUND,
                                   f"回调事件不存在: {event_id}", status_code=404)
            return copy.deepcopy(event)

    def get_owned(self, tenant_id: str, event_id: str) -> CallbackEvent:
        event = self.get(event_id)
        if event.tenant_id != tenant_id:
            raise GatewayError(ErrorCode.TENANT_MISMATCH,
                               "事件不属于该租户，查询被隔离拒绝")
        return event

    def list_for_tenant(self, tenant_id: str) -> list[CallbackEvent]:
        with self.storage.lock:
            return [copy.deepcopy(e) for e in self.storage.events.values()
                    if e.tenant_id == tenant_id]
