"""审计记录落地与脱敏。

- 每次授权、拒绝与状态变更都调用 write()，生成可追溯的结构化记录。
- 敏感字段（secret/token/signature/authorization/password）落盘前脱敏。
- fail_open=False（默认）时文件写入失败抛 AuditWriteError，
  由调用方保证业务状态不静默半更新（见各服务的“先业务、后审计、失败补偿”约定）。
"""
from __future__ import annotations

import json
import os
import threading
import uuid

from app.logging_utils import get_logger, mask
from app.models import AuditEntry

logger = get_logger("audit")


class AuditWriteError(RuntimeError):
    """审计落地失败（默认致命：不得让业务状态静默半更新）。"""


class AuditLog:
    SENSITIVE_KEYS = {"secret", "token", "signature", "password", "authorization",
                      "client_secret"}

    def __init__(self, path: str = "", fail_open: bool = False) -> None:
        self.path = path
        self.fail_open = fail_open
        self.lock = threading.RLock()
        self.entries: list[AuditEntry] = []

    def _mask_context(self, context: dict | None) -> dict:
        masked: dict = {}
        for key, value in (context or {}).items():
            if key.lower() in self.SENSITIVE_KEYS:
                masked[key] = mask(str(value))
            elif isinstance(value, dict):
                masked[key] = self._mask_context(value)
            else:
                masked[key] = value
        return masked

    def write(self, tenant_id: str, action: str, result: str, reason: str,
              context: dict | None = None, *, at: float | None = None) -> AuditEntry:
        """追加一条审计。内存追加与文件落盘在同一把锁内顺序完成。"""
        entry = AuditEntry(
            audit_id=uuid.uuid4().hex,
            at=at if at is not None else _now(),
            tenant_id=tenant_id or "-",
            action=action,
            result=result,
            reason=reason,
            masked_context=self._mask_context(context),
        )
        with self.lock:
            # 先落盘再放入内存：若落盘失败，内存中也不会出现“已审计”假象
            if self.path:
                self._append_file(entry)
            self.entries.append(entry)
        logger.info("audit action=%s result=%s tenant=%s reason=%s ctx=%s",
                    action, result, entry.tenant_id, reason,
                    json.dumps(entry.masked_context, ensure_ascii=False, sort_keys=True))
        return entry

    def _append_file(self, entry: AuditEntry) -> None:
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            line = json.dumps({
                "audit_id": entry.audit_id, "at": entry.at,
                "tenant_id": entry.tenant_id, "action": entry.action,
                "result": entry.result, "reason": entry.reason,
                "context": entry.masked_context,
            }, ensure_ascii=False, sort_keys=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except Exception as exc:  # noqa: BLE001 - 统一转为审计失败
            if self.fail_open:
                logger.warning("audit write failed but fail_open=true: %s", exc)
                return
            raise AuditWriteError(str(exc)) from exc

    def query(self, tenant_id: str | None = None) -> list[AuditEntry]:
        with self.lock:
            if tenant_id in (None, "", "-"):
                return list(self.entries)
            return [e for e in self.entries if e.tenant_id == tenant_id]

    def reset(self) -> None:
        with self.lock:
            self.entries.clear()


def _now() -> float:
    import time
    return time.time()
