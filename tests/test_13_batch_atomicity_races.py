"""批量提交的失败原子性、并发唯一执行与重放配额口径。

覆盖边界：
* 提交收尾阶段底层存储写入失败：已执行动作随大事务整体不生效（无同意/变更残留、
  无审计/回调记录），幂等记录不会卡在 processing；同一 request_id 重试正常完成，
  结果稳定且只发一次回调；
* 同一 request_id 跨线程/跨进程并发提交：真正执行恰好一次，其余全部拿到与首次
  完全一致的结果，不出现 idempotency_in_progress 一类中间态报错；
* 并发重放（含并发窗口内才拿到结果的重放）不重复占用限流配额，只按整批 1 次计；
* 失败后重试成功时，用量同样只算首次成功执行的 1 次。
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
import unittest

from app.batch import BATCH_COLLECTIONS
from app.storage import Collection
from tests.support import GatewayTestCase

log = logging.getLogger("test.batch_atomicity")

_STORAGE_BOOM = RuntimeError("模拟底层存储写入失败（收尾阶段）")


def _install_storage_failure(testcase, gateway, *, fail_on: int):
    """让 store 两阶段提交的临时文件 staging 在目标集合上直接失败一次。

    fail_on 指定第几个被 stage 的集合（按集合名排序，0=最先序列化的集合）。
    因为 2PC 先 stage 全部临时文件、再统一 rename，stage 失败发生在任何正式文件
    被替换之前，因此必须观察到“整批零生效”。

    用 addCleanup 保证 patch 一定被还原（即使断言失败也不污染后续用例）。
    """
    original_stage = Collection._stage_temp
    state = {"failed": False}

    def patched_stage(self, data):
        order = sorted(set(BATCH_COLLECTIONS))
        is_target = os.path.basename(self._path) == f"{order[fail_on]}.json"
        if is_target and not state["failed"]:
            state["failed"] = True
            raise _STORAGE_BOOM
        return original_stage(self, data)

    Collection._stage_temp = patched_stage
    testcase.addCleanup(setattr, Collection, "_stage_temp", original_stage)
    return state


def _count(gateway, collection: str) -> int:
    return len(gateway.store.collection(collection).list_items())


class BatchStorageFailureTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")

    def test_storage_failure_during_finalize_rolls_back_everything(self):
        gw = self.gateway
        cid = gw.consents.create("t1", "acct-1", ["accounts:read"], 3600)["consent_id"]
        gw.consents.authorise("t1", cid)
        actions = [
            {"action": "create", "resource": "acct-2", "scopes": ["payments:write"],
             "ttl_seconds": 600},
            {"action": "revoke", "consent_id": cid},
        ]
        consent_before = _count(gw, "consents")
        callback_before = _count(gw, "callbacks")
        audit_before = _count(gw, "audit")

        # 在 2PC 的每个 stage 位置分别注入一次失败，保证不只覆盖单一集合
        for pos in range(len(BATCH_COLLECTIONS)):
            with self.subTest(stage_position=pos):
                _install_storage_failure(self, gw, fail_on=pos)
                with self.assertRaises(RuntimeError):
                    gw.batch.submit("t1", f"boom-{pos}", actions)

                # 整批零生效：业务集合/回调/审计都没有新增
                assert _count(gw, "consents") == consent_before, \
                    (_count(gw, "consents"), consent_before)
                assert _count(gw, "callbacks") == callback_before
                assert _count(gw, "audit") == audit_before
                # 被撤的同意仍然 authorised：revoke 没有半生效
                assert gw.consents.get("t1", cid)["status"] == "authorised"
                # 幂等记录不存在（没有任何 completed/processing 残留）
                idem = gw.store.collection("idempotency").get(f"t1|boom-{pos}")
                assert idem is None, idem
                # 回调事件完全没登记
                from app.errors import CallbackNotFoundError

                with self.assertRaises(CallbackNotFoundError):
                    gw.callbacks.status(f"evt-consent-{cid}")
                log.info("stage 位置 %d 注入失败：整批零生效，重试未被挡", pos)

        # 同一 request_id 重试可以正常完成并拿到稳定结果（挑最后一个位置的键）
        out = gw.batch.submit("t1", "boom-4", actions)
        assert out["replayed"] is False
        assert out["summary"] == {"total": 2, "succeeded": 2, "failed": 0}, out["summary"]
        assert gw.consents.get("t1", cid)["status"] == "revoked"
        # 首次执行只发一次回调
        cb = gw.callbacks.status(f"evt-consent-{cid}")
        assert cb["attempts"] == 1 and cb["status"] == "delivered", cb
        # 再次提交同一 request_id：标准重放，结果一致、回调不重发
        replay = gw.batch.submit("t1", "boom-4", actions)
        assert replay["replayed"] is True
        assert replay["results"] == out["results"]
        assert gw.callbacks.status(f"evt-consent-{cid}")["attempts"] == 1
        log.info("失败后同 request_id 重试成功并稳定；回调只发一次")

    def test_failed_request_id_retry_consumes_quota_once(self):
        """通过 HTTP：收尾失败（不占配额，因为守卫回滚），重试成功占且仅占 1 次。"""
        key = self.issue_key("t1")
        h = key["headers"]
        payload = {"request_id": "http-boom", "actions": [
            {"action": "create", "resource": "acct-9", "scopes": ["accounts:read"],
             "ttl_seconds": 60},
        ]}
        from fastapi.testclient import TestClient as _TC
        raw_client = _TC(self.app, raise_server_exceptions=False)
        self.addCleanup(raw_client.close)
        _install_storage_failure(self, self.gateway, fail_on=0)
        r = raw_client.post("/t/t1/consents/batch", json=payload, headers=h)
        # 存储故障冒出到最外层：不做业务错误包装，本地直接 500
        assert r.status_code == 500, r.status_code

        usage_empty = self.client.get(
            "/t/t1/usage", headers=h,
            params={"endpoint": "POST /consents/batch"},
        ).json()
        assert usage_empty == {"rate": 0, "quota": 0}, usage_empty

        # 同 request_id 重试成功
        r2 = self.client.post("/t/t1/consents/batch", json=payload, headers=h)
        assert r2.status_code == 200 and r2.json()["replayed"] is False
        r3 = self.client.post("/t/t1/consents/batch", json=payload, headers=h)
        assert r3.status_code == 200 and r3.json()["replayed"] is True

        usage = self.client.get(
            "/t/t1/usage", headers=h,
            params={"endpoint": "POST /consents/batch"},
        ).json()
        assert usage == {"rate": 1, "quota": 1}, usage
        log.info("失败+重试+重放后用量=%s（只算首次成功的 1 次）", usage)


class BatchStaleClaimRecoveryTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")

    def test_legacy_processing_record_is_taken_over_and_completes(self):
        """旧版本可能留下永远 processing 的占位：新代码重试必须能接管并落定。"""
        gw = self.gateway
        actions = [
            {"action": "create", "resource": "acct-1", "scopes": ["accounts:read"],
             "ttl_seconds": 600},
        ]
        # 手工造一条旧版卡死的 processing 记录（模拟故障现场）
        fp = gw.batch.fingerprint(actions)
        gw.store.collection("idempotency").put("t1|stuck-1", {
            "tenant_id": "t1", "request_id": "stuck-1",
            "fingerprint": fp, "status": "processing",
            "created_at": self.now - 999, "finished_at": None, "results": None,
        })
        # 旧版故障现场：合作方会一直被 in_progress 挡住；现在重试应正常完成
        out = gw.batch.submit("t1", "stuck-1", actions)
        assert out["replayed"] is False, out
        assert out["summary"]["succeeded"] == 1
        rec = gw.store.collection("idempotency").get("t1|stuck-1")
        assert rec["status"] == "completed"
        # 再提交即为标准重放
        again = gw.batch.submit("t1", "stuck-1", actions)
        assert again["replayed"] is True
        assert again["results"] == out["results"]
        log.info("旧版 processing 卡死占位被接管，request_id 恢复正常幂等")


class BatchOutboxRecoveryTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")

    def test_committed_but_undelivered_callback_is_recovered(self):
        """事务已提交、首次投递未发生（模拟崩溃）：recover_undelivered 补投且不重复。"""
        gw = self.gateway
        cid = gw.consents.create("t1", "acct-1", ["accounts:read"], 3600)["consent_id"]
        gw.consents.authorise("t1", cid)
        # 让首次投递（事务提交后的 deliver_pending）直接抛异常，模拟进程在投递前/中死亡
        gw.callbacks._sender = lambda record: (_ for _ in ()).throw(
            RuntimeError("模拟首次投递时进程崩溃"))
        actions = [{"action": "revoke", "consent_id": cid}]
        out = gw.batch.submit("t1", "outbox-1", actions)
        assert out["replayed"] is False
        cb = gw.callbacks.status(f"evt-consent-{cid}")
        assert cb["status"] == "pending" and cb["attempts"] == 1, cb
        # 业务已提交（revoke 生效），回调 pending 待补；恢复投递器后扫描
        gw.callbacks._sender = lambda record: None
        # attempts==0、到点时间停在创建时刻：这正是“提交后未投递”的记录形态
        gw.store.collection("callbacks").update_atomic(
            f"evt-consent-{cid}",
            lambda rec: {**rec, "attempts": 0, "attempt_log": [],
                         "next_attempt_at": self.now - 10,
                         "last_error": None,
                         "created_at": self.now - 10},
        )
        recovered = gw.callbacks.recover_undelivered(grace_seconds=2.0)
        assert recovered == 1, recovered
        cb2 = gw.callbacks.status(f"evt-consent-{cid}")
        assert cb2["status"] == "delivered" and cb2["attempts"] == 1, cb2
        # 再恢复一次：不会重复投递
        assert gw.callbacks.recover_undelivered(grace_seconds=2.0) == 0
        log.info("outbox 未投递事件被补投 1 次，重复扫描不重发")


class BatchThreadConcurrencyTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")

    def test_concurrent_threads_same_request_id_all_get_first_result(self):
        gw = self.gateway
        cid = gw.consents.create("t1", "acct-1", ["accounts:read"], 3600)["consent_id"]
        gw.consents.authorise("t1", cid)
        actions = [
            {"action": "create", "resource": "acct-2", "scopes": ["payments:write"],
             "ttl_seconds": 600},
            {"action": "revoke", "consent_id": cid},
        ]
        n = 24
        barrier = threading.Barrier(n)
        outputs, errors = [], []
        lock = threading.Lock()

        def fire():
            barrier.wait()
            try:
                out = gw.batch.submit("t1", "thread-race", actions)
                with lock:
                    outputs.append(out)
            except Exception as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=fire) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, [type(e).__name__ for e in errors]
        assert len(outputs) == n
        first = next(o for o in outputs if not o["replayed"])
        replays = [o for o in outputs if o["replayed"]]
        assert len(replays) == n - 1, len(replays)
        for o in outputs:
            assert o["results"] == first["results"]
        # 业务副作用只发生一次
        assert _count(gw, "consents") == 2
        cb = gw.callbacks.status(f"evt-consent-{cid}")
        assert cb["attempts"] == 1, cb
        # revoke 的审计 + 批次提交审计等都只出现一次（按动作名粗查）
        batch_audits = [
            e for e in gw.audit.list("t1") if e["action"] == "consent_batch_submit"
        ]
        assert len(batch_audits) == 1, len(batch_audits)
        log.info("%d 线程并发：1 次执行 + %d 份一致重放，回调/审计各 1 次",
                 n, len(replays))

    def test_concurrent_http_replays_consume_quota_once(self):
        """并发窗口内拿到结果的重放也不占配额：24 并发后用量仍为整批 1 次。"""
        key = self.issue_key("t1")
        h = key["headers"]
        payload = {"request_id": "http-thread-race", "actions": [
            {"action": "create", "resource": "acct-1", "scopes": ["accounts:read"],
             "ttl_seconds": 600},
        ]}
        n = 24
        barrier = threading.Barrier(n)
        results, errors = [], []
        lock = threading.Lock()

        def fire():
            barrier.wait()
            try:
                r = self.client.post("/t/t1/consents/batch", json=payload, headers=h)
                with lock:
                    results.append(r)
            except Exception as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=fire) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, errors
        assert all(r.status_code == 200 for r in results), \
            [(r.status_code, r.text) for r in results]
        bodies = [r.json() for r in results]
        ids = {b["results"][0]["consent_id"] for b in bodies}
        assert len(ids) == 1, ids
        assert sum(1 for b in bodies if not b["replayed"]) == 1
        assert sum(1 for b in bodies if b["replayed"]) == n - 1

        usage = self.client.get(
            "/t/t1/usage", headers=h,
            params={"endpoint": "POST /consents/batch"},
        ).json()
        assert usage == {"rate": 1, "quota": 1}, usage
        log.info("%d HTTP 并发同 request_id：用量=%s（并发重放 0 占用）", n, usage)


# ---- 跨进程并发 ---------------------------------------------------------

_PROC_SNIPPET = """
import json, sys, tempfile
from app.config import Settings
from app.runtime import Gateway

data_dir, request_id = sys.argv[1], sys.argv[2]
st = Settings(
    data_dir=data_dir,
    default_rate_limit=1000, default_rate_window_seconds=60.0,
    default_quota=10000, default_quota_window_seconds=86400.0,
    callback_max_attempts=3, callback_backoff_base_seconds=0.01,
    callback_backoff_factor=2.0, max_payload_bytes=65536,
)
gw = Gateway(st)
try:
    gw.registry.register_tenant("t1", "T1")
except Exception:
    pass
try:
    out = gw.batch.submit("t1", request_id, [
        {"action": "create", "resource": "acct-1",
         "scopes": ["accounts:read"], "ttl_seconds": 3600},
    ])
    print(json.dumps({"consent_id": out["results"][0]["consent_id"],
                      "replayed": out["replayed"], "summary": out.get("summary")}))
except Exception as exc:
    print(json.dumps({"error": type(exc).__name__, "code": getattr(exc, "code", None)}))
finally:
    gw.close()
"""


class BatchCrossProcessTest(unittest.TestCase):
    def test_concurrent_processes_all_get_stable_first_result(self):
        tmp = tempfile.mkdtemp()
        procs = [
            subprocess.Popen(
                [sys.executable, "-c", _PROC_SNIPPET, tmp, "proc-atomic"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            for _ in range(4)
        ]
        outs = []
        for p in procs:
            stdout, stderr = p.communicate(timeout=60)
            assert p.returncode == 0, stderr.decode()
            outs.append(json.loads(stdout.decode().strip().splitlines()[-1]))

        log.info("跨进程并发同 request_id 结果=%s", outs)
        # 不允许任何 in_progress/冲突错误
        assert all("error" not in o for o in outs), outs
        ids = {o["consent_id"] for o in outs}
        assert len(ids) == 1, outs
        assert sum(1 for o in outs if not o["replayed"]) == 1, outs
        assert sum(1 for o in outs if o["replayed"]) == 3, outs
        # 磁盘上只有一个同意
        files = [f for f in os.listdir(tmp) if f == "consents.json"]
        assert files
        with open(os.path.join(tmp, "consents.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        assert len(data) == 1, len(data)


if __name__ == "__main__":
    unittest.main()
