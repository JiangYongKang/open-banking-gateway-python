"""可注入时钟：测试中可手动推进时间，验证过期与退避。"""
from __future__ import annotations

import time


class Clock:
    def __init__(self) -> None:
        self._offset = 0.0

    def now(self) -> float:
        return time.time() + self._offset

    def advance(self, seconds: float) -> None:
        self._offset += seconds

    def reset(self) -> None:
        self._offset = 0.0
