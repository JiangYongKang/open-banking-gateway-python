"""合作方自助只读视图：按本租户同意查看近期访问结果与回调投递情况。

硬约束：
* 严格租户隔离：只能查看本租户名下同意；访问他人同意与“不存在”完全同形
  （抛 ConsentNotFoundError），不泄漏其它租户同意是否存在；
* 纯只读：本模块不写任何集合、不写审计、不经限流计数，查询本身绝不产生副作用，
  也不影响正常业务的用量口径；
* 数据来源是已落地的审计集合与回调集合的快照，按时间排序返回。
"""
from __future__ import annotations

from .errors import ConsentNotFoundError

#: 单次视图返回的最大条目数，防止无界读取
MAX_VIEW_ITEMS = 200

#: 与某个同意关联的回调事件 id 前缀规则（见 main/batch 的确定性派生）
_CONSENT_EVENT_PREFIXES = ("evt-consent-", "evt-batch-")


class ConsentViewService:
    def __init__(self, store, consents, *, clock=None) -> None:
        self._store = store
        self._consents = consents
        self._clock = clock

    def _require_owned(self, tenant_id: str, consent_id: str) -> dict:
        rec = self._store.collection("consents").get(consent_id)
        if rec is None or rec.get("tenant_id") != tenant_id:
            raise ConsentNotFoundError(
                f"同意 {consent_id!r} 不存在", tenant_id=tenant_id
            )
        return rec

    @staticmethod
    def _cap(limit: int | None) -> int:
        if limit is None or limit <= 0:
            return 50
        return min(int(limit), MAX_VIEW_ITEMS)

    def access_results(self, tenant_id: str, consent_id: str, *,
                       limit: int | None = None) -> dict:
        """该同意近期的访问闸门结果：放行（resource_access）与各类拒绝（consent_access）。"""
        self._require_owned(tenant_id, consent_id)
        cap = self._cap(limit)
        entries = [
            {
                "ts": e["ts"],
                "result": e["result"],
                "action": e["action"],
                "resource": (e.get("detail") or {}).get("resource"),
                "scope": (e.get("detail") or {}).get("scope"),
                "reason": (e.get("detail") or {}).get("reason"),
            }
            for e in self._store.collection("audit").list_items()
            if e.get("tenant_id") == tenant_id
            and (e.get("detail") or {}).get("consent_id") == consent_id
            and e.get("action") in ("consent_access", "resource_access")
        ]
        entries.sort(key=lambda x: x["ts"])
        return {"consent_id": consent_id, "count": len(entries[-cap:]),
                "access_results": entries[-cap:]}

    def callback_deliveries(self, tenant_id: str, consent_id: str, *,
                            limit: int | None = None) -> dict:
        """该同意关联的回调投递情况（状态、尝试次数、每次尝试日志）。"""
        self._require_owned(tenant_id, consent_id)
        cap = self._cap(limit)
        marker_single = f"evt-consent-{consent_id}"
        marker_batch = f"-{consent_id}-"

        def _related(rec: dict) -> bool:
            if rec.get("tenant_id") != tenant_id:
                return False
            event_id = rec.get("event_id", "")
            if not event_id.startswith(_CONSENT_EVENT_PREFIXES):
                return False
            return event_id == marker_single or marker_batch in event_id

        records = [
            {
                "event_id": rec["event_id"],
                "event_type": rec.get("event_type"),
                "status": rec.get("status"),
                "attempts": rec.get("attempts"),
                "created_at": rec.get("created_at"),
                "updated_at": rec.get("updated_at"),
                "delivered_at": rec.get("delivered_at"),
                "next_attempt_at": rec.get("next_attempt_at"),
                "last_error": rec.get("last_error"),
                "attempt_log": rec.get("attempt_log", []),
            }
            for rec in self._store.collection("callbacks").list_items()
            if _related(rec)
        ]
        records.sort(key=lambda x: x["created_at"] or 0.0)
        return {"consent_id": consent_id, "count": len(records[-cap:]),
                "callbacks": records[-cap:]}

    def overview(self, tenant_id: str, consent_id: str, *,
                 limit: int | None = None) -> dict:
        """合并视图：同意当前状态 + 近期访问结果 + 关联回调。纯只读。"""
        rec = self._require_owned(tenant_id, consent_id)
        access = self.access_results(tenant_id, consent_id, limit=limit)
        callbacks = self.callback_deliveries(tenant_id, consent_id, limit=limit)
        return {
            "consent_id": consent_id,
            "status": rec["status"],
            "resource": rec["resource"],
            "scopes": list(rec["scopes"]),
            "version": rec["version"],
            "expires_at": rec.get("expires_at"),
            "pending_amendments": [
                a["amendment_id"]
                for a in rec.get("amendments", [])
                if a["status"] == "pending"
            ],
            "access_results": access["access_results"],
            "callbacks": callbacks["callbacks"],
        }
