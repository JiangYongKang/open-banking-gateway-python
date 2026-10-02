"""同意动作批量提交 + 请求级幂等。

承诺：
* 一批动作在**同一个跨集合事务**内完成：consents / amendments / callbacks（outbox
  事件登记）/ audit / idempotency 记录一起落盘。落盘失败则全部不生效——不会出现
  “同意已经建出来、回调已发、但批次记录还停在处理中”的改了一半状态；
* 回调采用事务内 outbox：先在同一事务里幂等登记事件，事务成功后才做首次投递，
  因此整批回滚时绝不发出回调；同一事件最多投递一次，失败按回调服务既有退避重试；
* request_id 按“租户 + request_id”作用域：同标识**全链路只真正执行一次**，
  之后（包括并发窗口里等在后面的请求）一律拿到与首次完全一致的稳定结果；
* 同 request_id 但动作内容不同 -> ``idempotency_conflict``；
* 并发（多线程/多进程）同一 request_id：通过存储目录下的 per-key flock 串行，
  落败方等首个完成后直接读首次结果，不会收到“处理中/冲突”的中间态报错；
* 若执行者在把结果落定前崩溃或落盘失败，记录会停在 processing，后续重试者在
  拿到键锁后接管执行（stale claim takeover），结果最终稳定落定一次；
* 单项动作的业务失败只回滚该项（事务内快照复位），不影响其它项，不留半状态。
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import logging
import os
import time
from typing import Self

from .audit import make_entry
from .errors import (
    GatewayError,
    IdempotencyConflictError,
    ValidationError,
)
from .models import ConsentStatus

ALLOWED_ACTIONS = (
    "create", "authorise", "revoke", "amend_request", "amend_approve",
)

log = logging.getLogger("obg.batch")


def _canonical(actions: list[dict]) -> str:
    """对动作列表做规范化 JSON（键排序），用于幂等指纹。"""
    return json.dumps(actions, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _fingerprint(actions: list[dict]) -> str:
    return hashlib.sha256(_canonical(actions).encode("utf-8")).hexdigest()


class _BatchKeyLock:
    """同一 request_id 的跨线程 + 跨进程互斥键锁。

    每个键对应存储目录下 ``batch-locks/<sha256(key)>.lock``。每次使用都独立
    ``open`` 一个文件描述符并加 flock 排他锁：独立 fd 上的 flock 在同进程
    线程之间同样互斥，因此一把锁同时覆盖多线程与多进程；进程崩溃时内核自动
    释放文件锁，不会留下需要人工清理的“永久处理中”。
    """

    def __init__(self, store, idem_key: str) -> None:
        lock_dir = os.path.join(store.data_dir, "batch-locks")
        os.makedirs(lock_dir, exist_ok=True)
        name = hashlib.sha256(idem_key.encode("utf-8")).hexdigest()
        self._path = os.path.join(lock_dir, f"{name}.lock")
        self._fh = None

    def __enter__(self) -> Self:
        self._fh = open(self._path, "a+")
        fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._fh is not None:
            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            finally:
                self._fh.close()
                self._fh = None


class BatchSlot:
    """``prepare`` 判定“本次需要真正执行”后持有的执行槽：握有键锁直到落定。"""

    def __init__(self, service: BatchService, tenant_id: str, request_id: str,
                 idem_key: str, fingerprint: str, actions: list[dict],
                 created_at: float) -> None:
        self._service = service
        self.tenant_id = tenant_id
        self.request_id = request_id
        self.idem_key = idem_key
        self.fingerprint = fingerprint
        self.actions = actions
        self.created_at = created_at
        self._lock = _BatchKeyLock(service._store, idem_key)
        self._held = False

    def acquire(self) -> BatchSlot:
        self._lock.__enter__()
        self._held = True
        return self

    def release(self) -> None:
        if self._held:
            self._held = False
            self._lock.__exit__(None, None, None)

    def execute(self) -> dict:
        return self._service._execute_slot(self)


class BatchService:
    def __init__(self, store, consents, amendments, audit=None, callbacks=None,
                 *, clock=time.time) -> None:
        self._store = store
        self._consents = consents
        self._amendments = amendments
        self._audit = audit
        self._callbacks = callbacks
        self._clock = clock

    def replay_result(self, tenant_id: str, request_id: str,
                      fingerprint: str) -> dict | None:
        """只读预判：若该 request_id 已完成则返回既有结果，否则 None。

        用于让幂等重放完全绕开限流配额（不重复扣额度）。并发窗口里首个仍在
        执行时返回 None，由 prepare/键锁等待首个完成后再返回稳定结果。
        """
        rec = self._store.collection("idempotency").get(f"{tenant_id}|{request_id}")
        if rec is None or rec["status"] != "completed":
            return None
        if rec["fingerprint"] != fingerprint:
            raise IdempotencyConflictError(
                "request_id 已被用于其它请求内容", tenant_id=tenant_id
            )
        return self._replay_payload(request_id, fingerprint, rec["results"])

    @staticmethod
    def _replay_payload(request_id: str, fingerprint: str, results: list) -> dict:
        return {"request_id": request_id, "replayed": True,
                "fingerprint": fingerprint, "results": results}

    # ---- 校验 ------------------------------------------------------------

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

    def prepare(self, tenant_id: str, request_id: str, actions: list[dict]):
        """阶段一：校验 + 在 per-key 键锁内判定本次是“重放”还是“执行”。

        返回两种结果之一：
        * dict：该 request_id 已完成，直接是可返回给调用方的稳定重放结果
          （键锁已释放）；
        * :class:`BatchSlot`：本线程/进程是唯一执行者，键锁持有至
          ``slot.execute()`` 结束；调用方（HTTP 层）可在 prepare 与 execute
          之间加限流，保证并发落败方/重放完全不占配额。
        """
        if not request_id or not isinstance(request_id, str):
            raise ValidationError("request_id 不能为空")
        self._validate(actions)
        fingerprint = _fingerprint(actions)
        idem_key = f"{tenant_id}|{request_id}"

        slot = BatchSlot(self, tenant_id, request_id, idem_key,
                          fingerprint, actions, self._clock()).acquire()
        try:
            outcome = self._store.atomic(
                ["idempotency"],
                lambda idem: self._claim(idem_key, tenant_id, request_id,
                                         fingerprint, idem),
            )
        except BaseException:
            slot.release()
            raise
        if outcome["kind"] == "replay":
            slot.release()
            return self._replay_payload(request_id, fingerprint, outcome["results"])
        # claimed（含对崩溃残留 processing 记录的接管）：持锁进入执行
        slot.created_at = outcome["created_at"]
        return slot

    def submit(self, tenant_id: str, request_id: str, actions: list[dict]) -> dict:
        """便捷入口：prepare + execute（服务内部/测试直接使用）。"""
        prepared = self.prepare(tenant_id, request_id, actions)
        if isinstance(prepared, BatchSlot):
            return prepared.execute()
        return prepared

    def _claim(self, idem_key, tenant_id, request_id, fingerprint,
               idem_proxy) -> dict:
        """键锁内的幂等判定：completed -> 重放；否则占位为 processing。"""
        existing = idem_proxy.get(idem_key)
        if existing is not None:
            if existing["fingerprint"] != fingerprint:
                raise IdempotencyConflictError(
                    "request_id 已被用于其它请求内容", tenant_id=tenant_id
                )
            if existing["status"] == "completed":
                return {"kind": "replay", "results": existing["results"]}
            # processing：只可能来自崩溃/落盘失败的前次执行者。键锁在我们手里，
            # 说明没有存活的执行者，安全接管重试（不返回中间态错误）。
        now = self._clock()
        idem_proxy.put(idem_key, {
            "tenant_id": tenant_id,
            "request_id": request_id,
            "fingerprint": fingerprint,
            "status": "processing",
            "created_at": now,
            "finished_at": None,
            "results": None,
        })
        return {"kind": "claimed", "created_at": now}

    # ---- 阶段二：整批一个大事务，逐项执行 + outbox 回调 -------------------

    def _execute_slot(self, slot: BatchSlot) -> dict:
        tenant_id = slot.tenant_id
        request_id = slot.request_id
        idem_key = slot.idem_key
        fingerprint = slot.fingerprint
        actions = slot.actions
        created_at = slot.created_at
        try:
            outcome = self._store.atomic(
                ["idempotency", "consents", "amendments", "callbacks", "audit"],
                lambda idem, consents, amendments, callbacks, audit: self._run_batch_tx(
                    idem_key, tenant_id, request_id, fingerprint, created_at,
                    actions, idem, consents, amendments, callbacks, audit,
                ),
            )
        finally:
            slot.release()
        results = outcome["results"]
        new_events = outcome["new_events"]
        # 事务已落定：对本次新登记的 outbox 事件做首次投递。投递器内部吞掉
        # 对端异常并按退避落重试计划；即使此处存储异常，事件也已随批落定，
        # 可由后台重试 / POST /admin/retry-now 继续，不影响批次结果。
        for event_id in new_events:
            try:
                self._callbacks._attempt_one(event_id, sleep_before=False)
            except Exception:
                log.warning("批量回调首次投递异常，留待重试 event_id=%s", event_id,
                            exc_info=True)
        return {"request_id": request_id, "replayed": False,
                "fingerprint": fingerprint,
                "summary": outcome["summary"], "results": results}

    def _run_batch_tx(self, idem_key, tenant_id, request_id, fingerprint, created_at,
                      actions, idem_proxy, consents_proxy, amendments_proxy,
                      callbacks_proxy, audit_proxy) -> dict:
        proxies = {"idem": idem_proxy, "consents": consents_proxy,
                   "amendments": amendments_proxy, "callbacks": callbacks_proxy,
                   "audit": audit_proxy}

        def _fail_result(index: int, action: dict, code: str, message: str) -> dict:
            kind = action.get("action")
            return {"index": index,
                    "action": kind if isinstance(kind, str) else None,
                    "ok": False, "error": {"code": code, "message": message}}

        results: list[dict] = []
        new_events: list[str] = []
        for index, action in enumerate(actions):
            # 每项执行前对全部集合做快照；该项失败则整体复位，做到单项失败
            # 只回滚自己那一项，此前已成功项与后续项都不受影响。
            backups = {name: copy.deepcopy(p.snapshot()) for name, p in proxies.items()}
            try:
                item = self._execute_one_in_tx(
                    tenant_id, index, action, proxies,
                )
            except GatewayError as exc:
                for name, p in proxies.items():
                    p.reset(backups[name])
                results.append(_fail_result(index, action, exc.code, exc.message))
                continue
            except Exception as exc:  # 防御：单项任何意外都不外溢，批继续
                for name, p in proxies.items():
                    p.reset(backups[name])
                results.append(_fail_result(index, action, "internal_error", str(exc)))
                continue
            # 结果里的 rec 是事务内活对象（后续项可能继续流转同一同意），
            # 深拷贝固化该项返回时刻的快照，避免被后续项改动串扰。
            item["result"]["result"] = copy.deepcopy(item["result"]["result"])
            results.append(item["result"])
            new_events.extend(item["new_events"])

        summary = {
            "total": len(results),
            "succeeded": sum(1 for r in results if r["ok"]),
            "failed": sum(1 for r in results if not r["ok"]),
        }
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
        return {"results": results, "summary": summary,
                "new_events": new_events}

    def _queue_callback(self, event_id, tenant_id, event_type, payload,
                        proxies) -> list[str]:
        """事务内幂等登记回调事件；只有本次新建的事件才返回（供提交后首投）。"""
        if self._callbacks is None:
            return []
        _record, created = self._callbacks.queue_in_tx(
            event_id, tenant_id, event_type, payload,
            proxies["callbacks"], proxies["audit"],
        )
        return [event_id] if created else []

    def _execute_one_in_tx(self, tenant_id: str, index: int, action: dict,
                           proxies: dict) -> dict:
        """在大事务代理上执行单项。抛 GatewayError 时由调用方复位该项快照。"""
        kind = action.get("action")
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
            rec = self._consents.create_in_tx(
                tenant_id, resource, scopes, float(ttl),
                proxies["consents"], proxies["audit"],
            )
            return {"result": {"index": index, "action": kind, "ok": True,
                               "consent_id": rec["consent_id"], "result": rec},
                    "new_events": []}

        consent_id = action.get("consent_id")
        if not consent_id:
            raise ValidationError(f"{kind} 需要 consent_id")

        if kind == "authorise":
            rec = self._consents.transition_in_tx(
                tenant_id, consent_id, ConsentStatus.AUTHORISED,
                "consent_authorise",
                proxies["consents"], proxies["audit"], proxies["amendments"],
            )
            new_events = self._queue_callback(
                f"evt-consent-{consent_id}", tenant_id, "consent.authorised",
                {"consent_id": consent_id, "resource": rec["resource"]}, proxies,
            )
            return {"result": {"index": index, "action": kind, "ok": True,
                               "consent_id": consent_id, "result": rec},
                    "new_events": new_events}

        if kind == "revoke":
            rec = self._consents.transition_in_tx(
                tenant_id, consent_id, ConsentStatus.REVOKED,
                "consent_revoke",
                proxies["consents"], proxies["audit"], proxies["amendments"],
            )
            new_events = self._queue_callback(
                f"evt-consent-{consent_id}", tenant_id, "consent.revoked",
                {"consent_id": consent_id}, proxies,
            )
            return {"result": {"index": index, "action": kind, "ok": True,
                               "consent_id": consent_id, "result": rec},
                    "new_events": new_events}

        if kind == "amend_request":
            rec = self._amendments.request_in_tx(
                tenant_id, consent_id,
                proxies["consents"], proxies["amendments"], proxies["audit"],
                add_scopes=action.get("add_scopes"),
                extend_seconds=action.get("extend_seconds"),
            )
            return {"result": {"index": index, "action": kind, "ok": True,
                               "consent_id": consent_id,
                               "amendment_id": rec["amendment_id"], "result": rec},
                    "new_events": []}

        # amend_approve
        amendment_id = action.get("amendment_id")
        if not amendment_id:
            raise ValidationError("amend_approve 需要 amendment_id")
        rec = self._amendments.approve_in_tx(
            tenant_id, amendment_id,
            proxies["consents"], proxies["amendments"], proxies["audit"],
        )
        new_events = self._queue_callback(
            f"evt-amendment-{amendment_id}", tenant_id,
            "consent.amendment_approved",
            {"consent_id": consent_id, "amendment_id": amendment_id}, proxies,
        )
        return {"result": {"index": index, "action": kind, "ok": True,
                           "consent_id": consent_id, "amendment_id": amendment_id,
                           "result": rec},
                "new_events": new_events}
