"""审计落地：敏感字段脱敏；写入失败显式抛出，由调用方决定回滚，避免半更新。"""
from __future__ import annotations

import time
import uuid
from typing import Any

from .crypto import mask_sensitive

# 出现在 detail 里、值必须脱敏的字段名（小写匹配）
SENSITIVE_KEYS = {
    "secret",
    "client_secret",
    "api_key",
    "token",
    "access_token",
    "authorization",
    "password",
    "signature",
}


def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        redacted = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in SENSITIVE_KEYS and isinstance(v, str):
                redacted[k] = mask_sensitive(v)
            else:
                redacted[k] = _redact(v)
        return redacted
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    return obj


def make_entry(
    action: str,
    *,
    tenant_id: str,
    result: str,
    detail: dict | None = None,
    clock=time.time,
) -> tuple[str, dict]:
    """构造 (entry_id, entry)，脱敏在此时完成。可在事务代理上直接 put。"""
    entry_id = f"aud-{uuid.uuid4().hex[:16]}"
    return entry_id, {
        "audit_id": entry_id,
        "ts": clock(),
        "action": action,
        "tenant_id": tenant_id,
        "result": result,  # allowed / denied / state_change / error
        "detail": _redact(detail or {}),
    }


class AuditLog:
    """审计记录追加到本地 store 的 ``audit`` 集合（仅追加、不修改历史）。"""

    def __init__(self, store, *, clock=time.time) -> None:
        self._coll = store.collection("audit")
        self._clock = clock

    def record(
        self,
        action: str,
        *,
        tenant_id: str,
        result: str,
        detail: dict | None = None,
    ) -> str:
        """写入一条审计记录，返回记录 ID。

        抛异常时代表审计未落地，调用方应让业务操作整体失败，
        而不是让“已完成的业务状态”静默存在却无审计。
        """
        entry_id, entry = make_entry(
            action, tenant_id=tenant_id, result=result, detail=detail, clock=self._clock
        )
        self._coll.put(entry_id, entry)
        return entry_id

    def list(self, tenant_id: str | None = None) -> list[dict]:
        items = self._coll.list_items()
        items.sort(key=lambda e: e["ts"])
        if tenant_id is not None:
            items = [e for e in items if e["tenant_id"] == tenant_id]
        return items
