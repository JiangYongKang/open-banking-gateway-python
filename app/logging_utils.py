"""测试与运行期日志：打印关键输入与判定依据。"""
from __future__ import annotations

import logging
import sys

_CONFIGURED = False


def _configure_root() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"))
    root = logging.getLogger("obg")
    root.setLevel(logging.INFO)
    root.handlers.clear()
    root.addHandler(handler)
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """获取统一格式 logger。"""
    _configure_root()
    if not name.startswith("obg"):
        name = f"obg.{name}"
    return logging.getLogger(name)


def mask(value: str | None, keep: int = 4) -> str:
    """敏感字段脱敏：空值返回 [none]，长度不足时全遮蔽，否则仅保留末尾 keep 位。"""
    if value is None or value == "":
        return "[none]"
    text = str(value)
    if len(text) <= keep:
        return "*" * len(text)
    return "*" * (len(text) - keep) + text[-keep:]
