"""同意动作批量提交与请求级幂等。

合作方可以在一次请求里混合提交多条同意动作（create / authorise / revoke /
request_amendment），并携带自己生成的 ``Idempotency-Key``：

* 同一个 (租户, 幂等键) 只生效一次：重复提交直接返回首次的稳定结果，
  不重复改状态、不重复扣额度、不重复触发回调；
* 首次执行在**单个跨集合事务**内完成所有条目的状态/审计/幂等记录落盘：
  某条动作不合法（如对已撤销同意申请变更）只让该条失败，其它合法条目照常落地，
  不会出现“改了一半、算了一半”——要么所有判定结果一起提交，要么整批不提交；
* 回调在事务提交后触发，事件 id 由 (批次序号, 同意 id, 动作类型) 确定性派生，
  配合回调自身的 event_id 幂等，重放批次绝不会产生第二次投递。
"""
from __future__ import annotations

import json
import time

from .audit import make_entry
from .errors import (
    BatchRequestError,
    GatewayError,
    IdempotencyReplayMismatchError,
    ValidationError,
)
from .models import ConsentStatus

#: 本批支持的动作 -> (中文说明)
SUPPORTED_ACTIONS = {"create", "authorise", "revoke", "request_amendment"}


def _fingerprint(actions: list[dict]) -> str:
    return json.dumps(actions, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _canonical_action(item: dict) -> dict:
    """把单条动作规范化为稳定形态，保证等价请求指纹一致。

    重点：数值类字段统一为 float（JSON 里 3600 与 360.0 语义相同），
    列表类字段缺省为 []，None 与缺省同义并被剔除。
    """
    out: dict = {"action": item["action"]}
    consent_id = item.get("consent_id")
    if consent_id is not None:
        out["consent_id"] = consent_id
    resource = item.get("resource")
    if resource is not None:
        out["resource"] = resource
    scopes = item.get("scopes")
    if scopes is not None:
        out["scopes"] = [str(s) for s in scopes]
    add_scopes = item.get("add_scopes")
    if add_scopes is not None:
        out["add_scopes"] = [str(s) for s in add_scopes]
    for key in ("ttl_seconds", "extend_ttl_seconds"):
        val = item.get(key)
        if val is not None:
            out[key] = float(val)
    return out


def _err_body(exc: Exception) -> dict:
    if isinstance(exc, GatewayError):
        return {"code": exc.code, "message": exc.message}
    return {"code": "internal_error", "message": f"{type(exc).__name__}: {exc}"}


class BatchService:
    def __init__(self, store, consents, audit=None, *, clock=time.time) -> None:
        self._store = store
        self._consents = consents
        self._audit = audit
        self._clock = clock

    @staticmethod
    def validate_actions(actions) -> list[dict]:
        if not isinstance(actions, list) or not actions:
            raise BatchRequestError("actions 必须是非空列表")
        normalized: list[dict] = []
        for idx, item in enumerate(actions):
            if not isinstance(item, dict):
                raise BatchRequestError(f"第 {idx} 条动作必须是对象")
            action = item.get("action")
            if action not in SUPPORTED_ACTIONS:
                raise BatchRequestError(
                    f"第 {idx} 条动作 {action!r} 不支持，"
                    f"可选：{sorted(SUPPORTED_ACTIONS)}"
                )
            normalized.append(_canonical_action(dict(item)))
        return normalized

    @staticmethod
    def _idem_key(tenant_id: str, request_id: str) -> str:
        return f"{tenant_id}|{request_id}"

    def lookup_replay(self, tenant_id: str, request_id: str,
                      fingerprint: str) -> dict | None:
        """只读探测：若 (租户, key) 已有记录且指纹一致，返回首次响应；
        指纹不一致抛 IdempotencyReplayMismatchError；无记录返回 None。

        用于在占用限流配额**之前**短路重放，保证重复提交不重复扣额度。
        """
        idem = self._store.collection("idempotency")
        existing = idem.get(self._idem_key(tenant_id, request_id))
        if existing is None:
            return None
        if existing.get("fingerprint") != fingerprint:
            raise IdempotencyReplayMismatchError(
                "同一 Idempotency-Key 的请求内容与首次提交不一致",
                tenant_id=tenant_id,
            )
        response = dict(existing["response"])
        response["replayed"] = True
        return response

    def execute(
        self,
        tenant_id: str,
        request_id: str,
        actions: list[dict],
        *,
        on_committed=None,
    ) -> dict:
        """执行一批动作。

        返回 ``{"request_id", "replayed", "results": [...]}；
        ``on_committed(events)`` 在首次事务提交成功后调用一次（用于事务外触发回调），
        重放时不调用。
        """
        if not request_id or not isinstance(request_id, str):
            raise ValidationError("缺少请求级幂等标识 Idempotency-Key",
                                  tenant_id=tenant_id)
        actions = self.validate_actions(actions)
        fingerprint = _fingerprint(actions)
        now = self._clock()

        def _tx(consents_coll, audit, idem):
            idem_id = self._idem_key(tenant_id, request_id)
            existing = idem.get(idem_id)
            if existing is not None:
                if existing.get("fingerprint") != fingerprint:
                    raise IdempotencyReplayMismatchError(
                        "同一 Idempotency-Key 的请求内容与首次提交不一致",
                        tenant_id=tenant_id,
                    )
                return {"replayed": True, "response": existing["response"]}

            results: list[dict] = []
            events: list[dict] = []
            for index, item in enumerate(actions):
                results.append(
                    self._run_one(
                        consents_coll, audit, tenant_id, item, index, now, events
                    )
                )

            response = {
                "request_id": request_id,
                "results": results,
            }
            idem.put(idem_id, {
                "tenant_id": tenant_id,
                "request_id": request_id,
                "fingerprint": fingerprint,
                "response": response,
                "created_at": now,
            })
            eid, entry = make_entry(
                "consent_batch",
                tenant_id=tenant_id,
                result="state_change",
                detail={"request_id": request_id, "count": len(actions),
                        "succeeded": sum(1 for r in results if r["ok"]),
                        "failed": sum(1 for r in results if not r["ok"])},
                clock=self._clock,
            )
            audit.put(eid, entry)
            return {"replayed": False, "response": response, "events": events}

        outcome = self._store.atomic(["consents", "audit", "idempotency"], _tx)
        # replayed 标志在返回时按本次是否命中既有记录组装，存储体内不含该标志，
        # 保证首次与任意次重放拿到的业务结果稳定一致。
        response = dict(outcome["response"])
        response["replayed"] = bool(outcome["replayed"])
        if outcome["replayed"]:
            return response
        if on_committed is not None:
            # 回调在事务外触发：状态已落盘，触发失败也不影响批次结果；
            # 事件 id 确定性派生 + trigger 幂等，任何重试/重放都不会重复投递。
            on_committed(outcome.get("events", []))
        return response

    # ---- 单条动作（锁内） ------------------------------------------------

    def _run_one(self, consents_coll, audit, tenant_id, item, index, now, events):
        action = item["action"]
        try:
            if action == "create":
                resource = item.get("resource")
                scopes = item.get("scopes")
                ttl = item.get("ttl_seconds")
                self._consents._validate_create(resource, scopes, ttl, tenant_id)
                rec = self._consents.create_locked(
                    consents_coll, audit, tenant_id, resource, scopes, float(ttl), now
                )
                events.append({"kind": "create", "consent_id": rec["consent_id"],
                               "resource": rec["resource"]})
                return {"index": index, "action": action, "ok": True,
                        "consent_id": rec["consent_id"], "consent": rec}

            consent_id = item.get("consent_id")
            if not consent_id:
                raise ValidationError("该动作需要 consent_id", tenant_id=tenant_id)

            if action == "authorise":
                rec = self._consents.transition_locked(
                    consents_coll, audit, tenant_id, consent_id,
                    ConsentStatus.AUTHORISED, now, action="consent_authorise"
                )
                events.append({"kind": "authorise", "consent_id": consent_id,
                               "resource": rec["resource"]})
                return {"index": index, "action": action, "ok": True,
                        "consent_id": consent_id, "consent": rec}

            if action == "revoke":
                rec = self._consents.transition_locked(
                    consents_coll, audit, tenant_id, consent_id,
                    ConsentStatus.REVOKED, now, action="consent_revoke"
                )
                events.append({"kind": "revoke", "consent_id": consent_id})
                return {"index": index, "action": action, "ok": True,
                        "consent_id": consent_id, "consent": rec}

            if action == "request_amendment":
                add_scopes, extend = self._consents._validate_amendment(
                    item.get("add_scopes"),
                    item.get("extend_ttl_seconds", 0),
                    tenant_id,
                )
                out = self._consents.request_amendment_locked(
                    consents_coll, audit, tenant_id, consent_id,
                    add_scopes, extend, now,
                )
                return {"index": index, "action": action, "ok": True,
                        "consent_id": consent_id, "consent": out["consent"],
                        "amendment_id": out["amendment"]["amendment_id"]}

            raise BatchRequestError(f"未知动作 {action!r}")
        except Exception as exc:  # 单条失败隔离：记录结果，不中断整批
            return {"index": index, "action": action, "ok": False,
                    "consent_id": item.get("consent_id"),
                    "error": _err_body(exc)}
