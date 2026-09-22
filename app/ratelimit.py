"""按租户 + 接口的限流与配额。

策略：两级滑动窗口（短窗 rate / 长窗 quota），窗口内时间戳列表计数。

* ``acquire`` 在一次文件锁事务内完成“读窗口 -> 清理过期时间戳 -> 判定 -> 追加”，
  并发下计数不会丢失、重复或超发；
* 判定超限时回调直接抛出内部信号、不执行追加，因此被拒绝的请求不消耗额度，
  错误中带 ``retry_after``（最早何时可能腾出名额）；
* 返回的 :class:`Reservation` 提供 ``rollback``：后续业务处理失败
  （如同意校验拒绝）时归还本次占位；成功路径无需额外操作。
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from .errors import RateLimitError


@dataclass
class LimitConfig:
    rate_limit: int
    rate_window: float
    quota: int
    quota_window: float

    def to_dict(self) -> dict:
        return {
            "rate_limit": self.rate_limit,
            "rate_window": self.rate_window,
            "quota": self.quota,
            "quota_window": self.quota_window,
        }


def _purge(stamps: list[float], now: float, window: float) -> list[float]:
    return [t for t in stamps if t > now - window]


class _RateLimit(Exception):
    """内部信号：锁内判定超限，携带等待信息传出（不对外暴露）。"""

    def __init__(self, retry_after: float, kind: str, current: int, limits: "LimitConfig") -> None:
        super().__init__(kind)
        self.retry_after = retry_after
        self.kind = kind
        self.current = current
        self.limits = limits


class Reservation:
    """一次成功的限流占位。commit 为空操作（acquire 时已计数），rollback 归还占位。"""

    def __init__(self, coll, buckets: list[str], stamp: float) -> None:
        self._coll = coll
        self._buckets = buckets
        self._stamp = stamp
        self._rolled_back = False

    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        if self._rolled_back:
            return
        self._rolled_back = True

        def _rollback(data: dict) -> None:
            for bucket in self._buckets:
                state = data.get(bucket)
                if state:
                    try:
                        state["stamps"].remove(self._stamp)
                    except ValueError:
                        pass

        self._coll.modify(_rollback)


class RateLimiter:
    def __init__(self, store, *, clock=time.time) -> None:
        self._coll = store.collection("ratelimits")
        self._clock = clock

    @staticmethod
    def bucket(tenant_id: str, endpoint: str, kind: str) -> str:
        return f"{tenant_id}|{endpoint}|{kind}"

    def acquire(self, tenant_id: str, endpoint: str, limits: LimitConfig) -> Reservation:
        now = self._clock()
        rate_bucket = self.bucket(tenant_id, endpoint, "rate")
        quota_bucket = self.bucket(tenant_id, endpoint, "quota")

        def _try(data: dict) -> None:
            rate_state = data.get(rate_bucket) or {"stamps": []}
            quota_state = data.get(quota_bucket) or {"stamps": []}
            rate_stamps = _purge(rate_state["stamps"], now, limits.rate_window)
            quota_stamps = _purge(quota_state["stamps"], now, limits.quota_window)

            if len(rate_stamps) >= limits.rate_limit:
                raise _RateLimit(
                    rate_stamps[0] + limits.rate_window - now,
                    "rate", len(rate_stamps), limits,
                )
            if len(quota_stamps) >= limits.quota:
                raise _RateLimit(
                    quota_stamps[0] + limits.quota_window - now,
                    "quota", len(quota_stamps), limits,
                )
            rate_stamps.append(now)
            quota_stamps.append(now)
            data[rate_bucket] = {"stamps": rate_stamps}
            data[quota_bucket] = {"stamps": quota_stamps}

        try:
            self._coll.modify(_try)
        except _RateLimit as rl:
            err = RateLimitError(f"触发{rl.kind}上限: {endpoint}", tenant_id=tenant_id)
            err.retry_after = max(0.0, rl.retry_after)
            err.limit_kind = rl.kind
            err.current = rl.current
            err.limit_config = rl.limits.to_dict()
            raise err
        return Reservation(self._coll, [rate_bucket, quota_bucket], now)

    def usage(self, tenant_id: str, endpoint: str, limits: LimitConfig) -> dict:
        now = self._clock()

        def _read(data: dict) -> dict:
            out = {}
            for kind, window in (("rate", limits.rate_window), ("quota", limits.quota_window)):
                state = data.get(self.bucket(tenant_id, endpoint, kind)) or {"stamps": []}
                out[kind] = len(_purge(state["stamps"], now, window))
            return out

        return _read(self._coll.modify(lambda data: None))
