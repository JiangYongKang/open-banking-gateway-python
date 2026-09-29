"""合作方自助只读视图：按同意查看近期访问结论与关联回调投递。

保证：
* 严格租户隔离：访问他人/不存在的同意统一抛 consent_not_found（不泄漏存在性）；
* 纯只读：只用 Collection 的快照读，不写业务、不写审计、不触碰限流计数，
  因此不会影响正常业务的用量口径。
"""
from __future__ import annotations

from .errors import ConsentNotFoundError

# 访问结论相关的审计动作：放行 + 闸门拒绝
_ACCESS_ACTIONS = ("resource_access", "consent_access")
_DENY_REASON_LABEL = {
    "consent_revoked": "revoked",
    "consent_expired": "expired",
    "consent_not_authorised": "not_authorised",
    "consent_resource_mismatch": "resource_mismatch",
    "consent_scope_missing": "scope_missing",
}


class InsightService:
    def __init__(self, store, *, recent_limit: int = 50) -> None:
        self._store = store
        self._recent_limit = recent_limit

    def consent_insight(self, tenant_id: str, consent_id: str) -> dict:
        """返回同意概要 + 近期访问结果 + 关联回调投递（仅本租户名下同意）。"""
        consents = self._store.collection("consents")
        rec = consents.get(consent_id)
        if rec is None or rec.get("tenant_id") != tenant_id:
            # 跨租户与不存在完全同形处理
            raise ConsentNotFoundError(
                f"同意 {consent_id!r} 不存在", tenant_id=tenant_id
            )

        access = self._recent_access(tenant_id, consent_id)
        callbacks = self._related_callbacks(tenant_id, consent_id)
        pending_amendment = self._pending_amendment(tenant_id, consent_id)
        return {
            "consent": {
                "consent_id": rec["consent_id"],
                "tenant_id": rec["tenant_id"],
                "resource": rec["resource"],
                "status": rec["status"],
                "scopes": list(rec["scopes"]),
                "version": rec["version"],
                "created_at": rec["created_at"],
                "authorised_at": rec.get("authorised_at"),
                "expires_at": rec.get("expires_at"),
                "revoked_at": rec.get("revoked_at"),
            },
            "pending_amendment": pending_amendment,
            "recent_access": access,
            "callbacks": callbacks,
        }

    # ---- 纯读聚合（不产生任何写入）---------------------------------------

    def _recent_access(self, tenant_id: str, consent_id: str) -> list[dict]:
        entries = self._store.collection("audit").list_items()
        rows = []
        for seq, e in enumerate(entries):
            if e.get("tenant_id") != tenant_id or e.get("action") not in _ACCESS_ACTIONS:
                continue
            detail = e.get("detail") or {}
            if detail.get("consent_id") != consent_id:
                continue
            if e["action"] == "resource_access":
                rows.append((seq, {
                    "ts": e["ts"], "outcome": "allowed", "reason": None,
                    "resource": detail.get("resource"),
                    "principal": detail.get("principal"),
                }))
            else:
                reason = detail.get("reason", "denied")
                rows.append((seq, {
                    "ts": e["ts"], "outcome": "denied",
                    "reason": _DENY_REASON_LABEL.get(reason, reason),
                    "resource": detail.get("resource"),
                    "scope": detail.get("scope"),
                }))
        # 时间倒序；同时间（固定时钟/同毫秒）按插入序号倒序，保证最新记录稳定在最前
        rows.sort(key=lambda item: (item[1]["ts"], item[0]), reverse=True)
        return [row for _, row in rows[: self._recent_limit]]

    def _related_callbacks(self, tenant_id: str, consent_id: str) -> list[dict]:
        records = self._store.collection("callbacks").list_items()
        out = []
        for rec in records:
            if rec.get("tenant_id") != tenant_id:
                continue
            payload = rec.get("payload") or {}
            related = payload.get("consent_id") == consent_id or (
                rec.get("event_type") == "consent.amendment_approved"
                and payload.get("amendment_id") in self._amendment_ids(consent_id)
            )
            if not related:
                continue
            out.append({
                "event_id": rec["event_id"],
                "event_type": rec["event_type"],
                "status": rec["status"],
                "attempts": rec["attempts"],
                "created_at": rec["created_at"],
                "delivered_at": rec.get("delivered_at"),
                "last_error": rec.get("last_error"),
            })
        out.sort(key=lambda r: r["created_at"], reverse=True)
        return out[: self._recent_limit]

    def _amendment_ids(self, consent_id: str) -> set[str]:
        return {
            a["amendment_id"]
            for a in self._store.collection("amendments").list_items()
            if a.get("consent_id") == consent_id
        }

    def _pending_amendment(self, tenant_id: str, consent_id: str) -> dict | None:
        for a in self._store.collection("amendments").list_items():
            if (
                a.get("tenant_id") == tenant_id
                and a.get("consent_id") == consent_id
                and a.get("status") == "pending"
            ):
                return {
                    "amendment_id": a["amendment_id"],
                    "add_scopes": list(a.get("add_scopes", [])),
                    "extend_seconds": a.get("extend_seconds"),
                    "result_scopes": list(a.get("result_scopes", [])),
                    "result_expires_at": a.get("result_expires_at"),
                    "created_at": a["created_at"],
                }
        return None
