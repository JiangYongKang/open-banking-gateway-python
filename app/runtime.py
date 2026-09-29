"""运行时容器：组装存储、各领域服务、本地 Webhook 投递器与后台重试线程。

本地模拟要点：
* Webhook 投递有两种模式：``local``（进程内直接调用接收逻辑，零网络）与
  ``http``（用 httpx POST 到租户配置的 URL，可指向本应用的 /callbacks/receive）；
* 可配置每个租户前 N 次投递失败，用于本地验证退避重试；
* 后台重试线程可显式 start/stop，停止时 join，不泄漏线程。
"""
from __future__ import annotations

import logging
import threading
import time

import httpx

from .audit import AuditLog
from .callbacks import CallbackDispatcher
from .config import Settings
from .consents import ConsentService
from .amendments import AmendmentService
from .batch import BatchService
from .insights import InsightService
from .ratelimit import LimitConfig, RateLimiter
from .storage import LocalStore
from .tenants import TenantRegistry
from .resources import MockBankService

log = logging.getLogger("obg.runtime")


class LocalWebhookSender:
    """根据租户 webhook 配置投递回调；local 模式零网络，http 模式走 httpx。"""

    def __init__(self, store: LocalStore, *, timeout: float = 2.0) -> None:
        self._webhooks = store.collection("webhooks")  # tenant_id -> config
        self._receipts = store.collection("receipts")  # event_id -> [receipt,...]
        self._timeout = timeout
        # 复用连接池；close() 时显式关闭，不泄漏连接
        self._http = httpx.Client(timeout=timeout)

    def close(self) -> None:
        self._http.close()

    def configure(
        self,
        tenant_id: str,
        *,
        mode: str = "local",
        url: str | None = None,
        fail_times: int = 0,
    ) -> dict:
        if mode not in ("local", "http"):
            raise ValueError("mode 必须是 local 或 http")
        if mode == "http" and not url:
            raise ValueError("http 模式必须提供 url")
        config = {"tenant_id": tenant_id, "mode": mode, "url": url,
                  "fail_times": int(fail_times), "fails_used": 0}
        self._webhooks.put(tenant_id, config)
        return config

    def _record_receipt(self, event_id: str, tenant_id: str, accepted: bool) -> None:
        self._receipts.update_atomic(
            event_id,
            lambda v: (v or []) + [{
                "event_id": event_id, "tenant_id": tenant_id,
                "accepted": accepted, "ts": time.time(),
            }],
            factory=list,
        )

    def list_receipts(self, event_id: str) -> list[dict]:
        return self._receipts.get(event_id, [])

    def __call__(self, record: dict) -> None:
        tenant_id = record["tenant_id"]
        event_id = record["event_id"]
        config = self._webhooks.get(tenant_id) or {"mode": "local", "fail_times": 0,
                                                   "fails_used": 0, "url": None}
        should_fail = config.get("fails_used", 0) < config.get("fail_times", 0)
        if should_fail:
            def _bump(data: dict) -> None:
                cfg = data.get(tenant_id)
                if cfg is not None and cfg.get("fails_used", 0) < cfg.get("fail_times", 0):
                    cfg["fails_used"] = cfg.get("fails_used", 0) + 1

            self._webhooks.modify(_bump)
            self._record_receipt(event_id, tenant_id, accepted=False)
            raise RuntimeError(f"模拟 webhook 投递失败（租户 {tenant_id} 配置的前 N 次失败）")

        if config.get("mode") == "http":
            resp = self._http.post(
                config["url"],
                json={"event_id": event_id, "event_type": record["event_type"],
                      "payload": record["payload"]},
                headers={"X-Event-Id": event_id, "X-Tenant-Id": tenant_id},
            )
            if resp.status_code >= 400:
                raise RuntimeError(f"webhook 返回 HTTP {resp.status_code}")
        else:
            self._record_receipt(event_id, tenant_id, accepted=True)
        log.info("callback delivered event_id=%s tenant=%s mode=%s",
                 event_id, tenant_id, config.get("mode"))


class Gateway:
    """所有服务与配置的组装根对象。"""

    def __init__(self, settings: Settings, *, clock=time.time, sleep=time.sleep) -> None:
        self.settings = settings
        self.clock = clock
        self.sleep = sleep
        self.store = LocalStore(settings.data_dir)
        self.audit = AuditLog(self.store, clock=clock)
        self.registry = TenantRegistry(self.store, self.audit, clock=clock)
        self.consents = ConsentService(self.store, self.audit, clock=clock)
        self.amendments = AmendmentService(
            self.store, self.audit, self.consents, clock=clock
        )
        # 同意终态化时，同事务作废挂在其上的待生效变更
        self.consents.amendment_void_hook = self.amendments.void_pending_in_tx
        self.limiter = RateLimiter(self.store, clock=clock)
        self.sender = LocalWebhookSender(self.store, timeout=settings.upstream_timeout_seconds)
        self.callbacks = CallbackDispatcher(
            self.store, self.audit,
            sender=self.sender, clock=clock, sleep=sleep,
            max_payload_bytes=settings.max_payload_bytes,
            max_attempts=settings.callback_max_attempts,
            backoff_base=settings.callback_backoff_base_seconds,
            backoff_factor=settings.callback_backoff_factor,
        )
        self.batch = BatchService(
            self.store, self.consents, self.amendments, self.audit, self.callbacks, clock=clock
        )
        self.insights = InsightService(self.store)
        self.bank = MockBankService(timeout=settings.upstream_timeout_seconds)
        self._retry_thread: threading.Thread | None = None
        self._stop = threading.Event()

    # ---- 限流守卫：成功才占额度，业务被拒/异常则回滚 ----------------------

    def default_limits(self) -> LimitConfig:
        return LimitConfig(
            rate_limit=self.settings.default_rate_limit,
            rate_window=self.settings.default_rate_window_seconds,
            quota=self.settings.default_quota,
            quota_window=self.settings.default_quota_window_seconds,
        )

    def guard(self, tenant_id: str, endpoint: str):
        """上下文管理器：进入即获取限流占位，退出时非成功则回滚。"""
        return _ReservationGuard(self.limiter, tenant_id, endpoint, self.default_limits())

    # ---- 后台重试线程 ----------------------------------------------------

    def start_retry_worker(self, interval: float = 0.05) -> None:
        if self._retry_thread is not None:
            return

        def _loop() -> None:
            while not self._stop.wait(interval):
                try:
                    self.callbacks.run_due_retries()
                except Exception:  # 重试线程不能因单条异常死掉
                    log.exception("retry worker iteration failed")

        self._retry_thread = threading.Thread(target=_loop, name="obg-retry", daemon=True)
        self._retry_thread.start()

    def stop_retry_worker(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._retry_thread is not None:
            self._retry_thread.join(timeout=timeout)
            self._retry_thread = None

    def close(self) -> None:
        """释放后台线程与连接池。"""
        self.stop_retry_worker()
        self.sender.close()


class _ReservationGuard:
    def __init__(self, limiter: RateLimiter, tenant_id: str, endpoint: str,
                 limits: LimitConfig) -> None:
        self._limiter = limiter
        self._tenant_id = tenant_id
        self._endpoint = endpoint
        self._limits = limits
        self._reservation = None
        self._committed = False

    @property
    def retry_after(self):
        return None

    def __enter__(self):
        self._reservation = self._limiter.acquire(
            self._tenant_id, self._endpoint, self._limits
        )
        return self

    def commit(self) -> None:
        if not self._committed:
            self._committed = True
            self._reservation.commit()

    def __exit__(self, exc_type, exc, tb) -> None:
        if not self._committed:
            # 业务抛错或被拒绝：归还占位，不消耗额度
            self._reservation.rollback()
        return None
