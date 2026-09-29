"""同意动作批量提交 + 请求级幂等。

约定：
* 一批动作逐项独立执行，每项给出成功/失败结果；单项失败只回滚自己那一项，
  不影响其它项，不留半状态；
* request_id 由合作方生成，按“租户 + request_id”作用域：重复提交只执行一次，
  之后始终返回首次的完整结果（不重复扣额度/发回调/改状态）；
* 同 request_id 但动作内容不同 -> ``idempotency_conflict``；
* 并发提交同一 request_id：进程内串行，跨进程通过存储中的处理标记二次确认。
"""
from __future__ import annotations

import hashlib
import json
import threading
import time

from .audit import make_entry
from .errors import (
    GatewayError,
    IdempotencyConflictError,
    IdempotencyInProgressError,
    ValidationError,
)

ALLOWED_ACTIONS = (
    "create", "authorise", "revoke", "amend_request", "amend_approve",
)


def _canonical(actions: list[dict]) -> str:
    """对动作列表做规范化 JSON（键排序），用于幂等指纹。"""
    return json.dumps(actions, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _fingerprint(actions: list[dict]) -> str:
    return hashlib.sha256(_canonical(actions).encode("utf-8")).hexdigest()


class BatchService:
    def __init__(self, store, consents, amendments, audit=None, callbacks=None,
                 *, clock=time.time) -> None:
        self._store = store
        self._consents = consents
        self._amendments = amendments
        self._audit = audit
        self._callbacks = callbacks
        self._clock = clock
        self._key_locks: dict[str, threading.Lock] = {}
        self._key_locks_guard = threading.Lock()

    def _lock_for(self, key: str) -> threading.Lock:
        """同 request_id 进程内串行：并发同单第二个线程等首个完成后读既有结果。"""
        with self._key_locks_guard:
            lock = self._key_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._key_locks[key] = lock
            return lock

    def replay_result(self, tenant_id: str, request_id: str,
                      fingerprint: str) -> dict | None:
        """只读预判：若该 request_id 已完成则返回既有结果，否则 None。

        用于让幂等重放完全绕开限流配额（不重复扣额度）。
        """
        rec = self._store.collection("idempotency").get(f"{tenant_id}|{request_id}")
        if rec is None or rec["status"] != "completed":
            return None
        if rec["fingerprint"] != fingerprint:
            raise IdempotencyConflictError(
                "request_id 已被用于其它请求内容", tenant_id=tenant_id
            )
        return {"request_id": request_id, "replayed": True,
                "fingerprint": fingerprint, "results": rec["results"]}

    # ---- 单项执行（每项独立 try，异常转结构化结果，不留半状态）-------------

    def _execute_one(self, tenant_id: str, index: int, action: dict) -> dict:
        kind = action.get("action")
        try:
            if not isinstance(kind, str):
                raise ValidationError("action 必须是字符串")
            if kind not in ALLOWED_ACTIONS:
                raise ValidationError(
                    f"不支持的动作 {kind!r}，允许: {', '.join(ALLOWED_ACTIONS)}"
                )

            if kind == "create":
                resource = action.get("resource")
                scopes = action.get("scopes")
                ttl = action.get("ttl_seconds")
                if not isinstance(scopes, list) or not scopes:
                    raise ValidationError("create 需要非空 scopes 列表")
                if ttl is None:
                    raise ValidationError("create 需要 ttl_seconds")
                rec = self._consents.create(tenant_id, resource, scopes, float(ttl))
                return {"index": index, "action": kind, "ok": True,
                        "consent_id": rec["consent_id"], "result": rec}

            consent_id = action.get("consent_id")
            if not consent_id:
                raise ValidationError(f"{kind} 需要 consent_id")

            if kind == "authorise":
                rec = self._consents.authorise(tenant_id, consent_id)
                self._trigger_callback(
                    tenant_id, f"evt-consent-{consent_id}",
                    "consent.authorised",
                    {"consent_id": consent_id, "resource": rec["resource"]},
                )
                return {"index": index, "action": kind, "ok": True,
                        "consent_id": consent_id, "result": rec}

            if kind == "revoke":
                rec = self._consents.revoke(tenant_id, consent_id)
                self._trigger_callback(
                    tenant_id, f"evt-consent-{consent_id}",
                    "consent.revoked", {"consent_id": consent_id},
                )
                return {"index": index, "action": kind, "ok": True,
                        "consent_id": consent_id, "result": rec}

            if kind == "amend_request":
                rec = self._amendments.request(
                    tenant_id, consent_id,
                    add_scopes=action.get("add_scopes"),
                    extend_seconds=action.get("extend_seconds"),
                )
                return {"index": index, "action": kind, "ok": True,
                        "consent_id": consent_id,
                        "amendment_id": rec["amendment_id"], "result": rec}

            # amend_approve
            amendment_id = action.get("amendment_id")
            if not amendment_id:
                raise ValidationError("amend_approve 需要 amendment_id")
            rec = self._amendments.approve(tenant_id, amendment_id)
            self._trigger_callback(
                tenant_id, f"evt-amendment-{amendment_id}",
                "consent.amendment_approved",
                {"consent_id": consent_id, "amendment_id": amendment_id},
            )
            return {"index": index, "action": kind, "ok": True,
                    "consent_id": consent_id, "amendment_id": amendment_id,
                    "result": rec}
        except GatewayError as exc:
            return {"index": index, "action": kind if isinstance(kind, str) else None,
                    "ok": False, "error": {"code": exc.code, "message": exc.message}}
        except Exception as exc:  # 防御：单项任何意外都不外溢，批继续
            return {"index": index, "action": kind if isinstance(kind, str) else None,
                    "ok": False,
                    "error": {"code": "internal_error", "message": str(exc)}}

    def _trigger_callback(self, tenant_id, event_id, event_type, payload) -> None:
        if self._callbacks is None:
            return
        # trigger 自身按 event_id 幂等；批量幂等由外层 request_id 保证不重复到这里
        self._callbacks.trigger(event_id, tenant_id, event_type, payload)

    def _validate(self, actions) -> None:
        if not isinstance(actions, list) or not actions:
            raise ValidationError("actions 必须是非空列表")
        if len(actions) > 100:
            raise ValidationError("单批最多 100 个动作")
        for i, a in enumerate(actions):
            if not isinstance(a, dict):
                raise ValidationError(f"第 {i} 项必须是对象")

    # ---- 公开 API --------------------------------------------------------

    @staticmethod
    def fingerprint(actions: list[dict]) -> str:
        """动作列表的幂等指纹（规范化 JSON 的 SHA-256）。"""
        return _fingerprint(actions)

    def submit(self, tenant_id: str, request_id: str, actions: list[dict]) -> dict:
        if not request_id or not isinstance(request_id, str):
            raise ValidationError("request_id 不能为空")
        self._validate(actions)
        fingerprint = _fingerprint(actions)
        idem_key = f"{tenant_id}|{request_id}"
        lock = self._lock_for(idem_key)

        with lock:
            # 阶段 1：独立事务检查/占位（不在此处嵌套执行业务事务，避免嵌套文件锁）
            claim = self._store.atomic(
                ["idempotency"],
                lambda idem: self._claim(idem_key, tenant_id, fingerprint, idem),
            )
            if claim["kind"] == "replay":
                return {"request_id": request_id, "replayed": True,
                        "fingerprint": fingerprint, "results": claim["results"]}
            if claim["kind"] == "in_progress":
                raise IdempotencyInProgressError(
                    "相同 request_id 的请求正在处理中", tenant_id=tenant_id
                )
            # claim == "claimed"：本线程是唯一执行者
            # 阶段 2：锁外逐项执行；每项自带事务，单项失败不外溢、不留半状态
            results = [self._execute_one(tenant_id, i, a) for i, a in enumerate(actions)]
            summary = {
                "total": len(results),
                "succeeded": sum(1 for r in results if r["ok"]),
                "failed": sum(1 for r in results if not r["ok"]),
            }
            # 阶段 3：独立事务写定结果 + 审计
            self._store.atomic(
                ["idempotency", "audit"],
                lambda idem, audit: self._complete(
                    idem_key, tenant_id, request_id, fingerprint,
                    claim["created_at"], results, summary, idem, audit
                ),
            )
            return {"request_id": request_id, "replayed": False,
                    "fingerprint": fingerprint, "summary": summary, "results": results}

    def _claim(self, idem_key, tenant_id, fingerprint, idem_proxy) -> dict:
        existing = idem_proxy.get(idem_key)
        if existing is not None:
            if existing["fingerprint"] != fingerprint:
                raise IdempotencyConflictError(
                    "request_id 已被用于其它请求内容", tenant_id=tenant_id
                )
            if existing["status"] == "processing":
                # 跨进程并发：首个仍在执行，绝不重复执行
                return {"kind": "in_progress"}
            return {"kind": "replay", "results": existing["results"]}
        now = self._clock()
        idem_proxy.put(idem_key, {
            "tenant_id": tenant_id,
            "request_id": idem_key.split("|", 1)[1],
            "fingerprint": fingerprint,
            "status": "processing",
            "created_at": now,
            "finished_at": None,
            "results": None,
        })
        return {"kind": "claimed", "created_at": now}

    def _complete(self, idem_key, tenant_id, request_id, fingerprint, created_at,
                  results, summary, idem_proxy, audit_proxy) -> None:
        idem_proxy.put(idem_key, {
            "tenant_id": tenant_id,
            "request_id": request_id,
            "fingerprint": fingerprint,
            "status": "completed",
            "created_at": created_at,
            "finished_at": self._clock(),
            "results": results,
            "summary": summary,
        })
        if self._audit is not None:
            eid, entry = make_entry(
                "consent_batch_submit",
                tenant_id=tenant_id,
                result="state_change",
                detail={"request_id": request_id, "fingerprint": fingerprint[:16],
                        **summary},
                clock=self._clock,
            )
            audit_proxy.put(eid, entry)
