"""本地模拟第三方调用方（不访问任何外部服务、不发起真实网络请求）。

URL 规则：
- 以 "fail://" 开头：始终失败（用于验证退避重试与最终死信）
- 含 ":transient:"：针对该“事件 + 回调地址”的前两次尝试失败，第三次起成功
- 其他：成功

每个 (event_id, url) 维护独立计数，互不污染。
"""
from __future__ import annotations

import threading
from collections import defaultdict

from app.logging_utils import get_logger

logger = get_logger("simulator")


class SimulatedCaller:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._attempt_counts: dict[tuple[str, str], int] = defaultdict(int)
        self.delivered: list[tuple[str, dict]] = []

    def post(self, event_id: str, url: str, payload: dict) -> tuple[bool, str]:
        """模拟一次 HTTP 投递，返回 (是否成功, 失败原因)。"""
        key = (event_id, url)
        with self._lock:
            self._attempt_counts[key] += 1
            attempt = self._attempt_counts[key]
            if url.startswith("fail://"):
                logger.info("simulated POST event=%s attempt=%d url=%s -> permanent fail",
                            event_id, attempt, url)
                return False, f"simulated permanent failure ({url})"
            if ":transient:" in url:
                if attempt <= 2:
                    logger.info("simulated POST event=%s attempt=%d -> transient fail",
                                event_id, attempt)
                    return False, f"simulated transient failure on attempt {attempt}"
            self.delivered.append((event_id, payload))
            logger.info("simulated POST event=%s attempt=%d url=%s -> success",
                        event_id, attempt, url)
            return True, ""

    def reset(self) -> None:
        with self._lock:
            self._attempt_counts.clear()
            self.delivered.clear()
