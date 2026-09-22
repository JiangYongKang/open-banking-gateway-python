"""按租户与按接口的限流和配额。

- 限流：固定 60s 窗口计数，键 (tenant, endpoint)；窗口滚动自动清零。
- 配额：按 UTC 日期计数 (tenant, date)。
- 策略：
    reject -> 超限立即拒绝（429），返回 retry_after_seconds；不消耗额度。
    delay  -> 在 settings.delay_timeout_seconds 内等待窗口重置后获取；
              超时仍未获取则按 RATE_LIMITED_TIMEOUT 拒绝，同样不消耗额度。
- 全部计数在存储锁内完成，保证并发下不丢失、不超发。
"""
from __future__ import annotations

import datetime as dt

from app.errors import ErrorCode, GatewayError
from app.logging_utils import get_logger
from app.models import WindowCounter

logger = get_logger("ratelimit")

WINDOW_SECONDS = 60.0


class RateLimitService:
    def __init__(self, storage, settings, clock, sleeper=None) -> None:  # noqa: ANN001
        self.storage = storage
        self.settings = settings
        self.clock = clock
        # sleeper 可注入（测试中由 Clock 推进虚拟时间），默认真实 sleep
        self._sleeper = sleeper or self._real_sleep

    @staticmethod
    def _real_sleep(seconds: float) -> None:
        import time
        time.sleep(max(0.0, seconds))

    def _limit_for(self, tenant_id: str, endpoint: str) -> int:
        specific = self.settings.rate_limit_per_minute.get(f"{tenant_id}:{endpoint}")
        if specific is not None:
            return specific
        return self.settings.rate_limit_default_per_minute

    def _quota_for(self, tenant_id: str) -> int:
        return self.settings.daily_quota.get(tenant_id,
                                             self.settings.daily_quota_default)

    def _current_date(self) -> str:
        return dt.datetime.fromtimestamp(self.clock.now(), tz=dt.UTC).strftime("%Y-%m-%d")

    def _window_remaining(self, window_start: float) -> float:
        return max(0.0, WINDOW_SECONDS - (self.clock.now() - window_start))

    def acquire(self, tenant_id: str, endpoint: str) -> None:
        """成功占用 1 个限流额度 + 1 个日配额；失败抛可区分异常且不消耗任何额度。"""
        limit = self._limit_for(tenant_id, endpoint)
        quota = self._quota_for(tenant_id)
        deadline = self.clock.now() + self.settings.delay_timeout_seconds
        key = (tenant_id, endpoint)

        while True:
            with self.storage.lock:
                now = self.clock.now()
                counter = self.storage.rate_counters.get(key)
                if counter is None or now - counter.window_start >= WINDOW_SECONDS:
                    counter = WindowCounter(window_start=now, value=0)
                    self.storage.rate_counters[key] = counter
                quota_key = (tenant_id, self._current_date())
                used_quota = self.storage.quota_counters.get(quota_key, 0)

                quota_exceeded = used_quota >= quota
                rate_exceeded = counter.value >= limit

                if not quota_exceeded and not rate_exceeded:
                    # 唯一的“消耗额度”点：锁内同时自增，计数不可能超发
                    counter.value += 1
                    self.storage.quota_counters[quota_key] = used_quota + 1
                    logger.info("acquire ok tenant=%s endpoint=%s rate=%d/%d quota=%d/%d",
                                tenant_id, endpoint, counter.value, limit,
                                used_quota + 1, quota)
                    return

                retry_after = self._window_remaining(counter.window_start)

            # ---- 锁外决定策略（不持有锁睡眠，避免阻塞其他租户/接口）----
            if quota_exceeded:
                # 日配额没有“本窗口内等待即可恢复”的语义，直接拒绝
                self._reject(ErrorCode.QUOTA_EXHAUSTED, tenant_id, endpoint,
                             "日配额已用尽", retry_after=0, limit=quota,
                             used=used_quota)
            if self.settings.rate_limit_action != "delay":
                self._reject(ErrorCode.RATE_LIMITED_REJECT, tenant_id, endpoint,
                             f"限流：每分钟上限 {limit}", retry_after=retry_after,
                             limit=limit, used=counter.value)
            wait = min(retry_after, deadline - self.clock.now())
            if wait <= 0:
                self._reject(ErrorCode.RATE_LIMITED_TIMEOUT, tenant_id, endpoint,
                             "延迟等待超时，仍被限流", retry_after=retry_after,
                             limit=limit, used=counter.value)
            logger.info("rate limited, sleeping %.3fs tenant=%s", wait, tenant_id)
            self._sleeper(wait)

    def _reject(self, code: ErrorCode, tenant_id: str, endpoint: str, message: str,
                *, retry_after: float, limit: int, used: int) -> None:
        # 被拒绝的请求不消耗额度：计数未在锁内自增，这里仅记录判定依据
        logger.warning("deny code=%s tenant=%s endpoint=%s used=%d limit=%d "
                       "retry_after=%.2f", code.value, tenant_id, endpoint, used,
                       limit, retry_after)
        raise GatewayError(code, message, details={
            "tenant_id": tenant_id, "endpoint": endpoint,
            "limit_per_minute": limit, "current": used,
            "retry_after_seconds": round(retry_after, 3),
            "policy": self.settings.rate_limit_action,
        })

    # ---- 测试/运维辅助 -------------------------------------------------
    def peek_rate(self, tenant_id: str, endpoint: str) -> int:
        with self.storage.lock:
            counter = self.storage.rate_counters.get((tenant_id, endpoint))
            if counter is None:
                return 0
            if self.clock.now() - counter.window_start >= WINDOW_SECONDS:
                return 0
            return counter.value

    def peek_quota(self, tenant_id: str) -> int:
        with self.storage.lock:
            return self.storage.quota_counters.get((tenant_id, self._current_date()), 0)
