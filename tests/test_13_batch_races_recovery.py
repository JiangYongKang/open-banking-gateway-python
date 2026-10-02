"""批量提交边界补强（bugfix）：

* 收尾阶段底层存储写入失败：整批全部不生效（同意/回调/审计/幂等记录均不落半状态），
  随后同 request_id 重试能正常完成并拿到稳定结果，回调只发一次；
* 同一 request_id 跨线程并发提交：只真正执行一次，其余线程拿到与首次完全一致的
  结果，不再出现 idempotency_in_progress 中间态报错；
* 跨进程并发提交：落败进程等待后拿到首次结果（而不是冲突报错）；
* 并发窗口里落败的重放请求不重复占用限流/配额；完成后的重放同样占 0；
  整批只对唯一执行者计 1 次。
"""
from __future__ import annotations

import json
import logging
import subprocess
import sys
import tempfile
import threading
import unittest

from app.config import Settings
from app.runtime import Gateway
from tests.support import GatewayTestCase

log = logging.getLogger("test.batch_races")


def _fail_once_on_collection(store, name: str, *, fail_on_call: int = 1,
                             exc: Exception | None = None) -> dict:
    """让 name 集合在第 fail_on_call 次落盘暂存（stage）时失败一次，之后恢复正常。

    失败发生在两阶段提交的“全部正式文件 rename 之前”，因此任何集合都不会被
    替换；用来模拟“快要收尾、底层存储突然写入失败”。

    fail_on_call=2 可跳过 prepare 阶段 claim 写入 processing 的那次暂存，
    精确打击整批事务最终落定的那一刻。
    """
    state = {"armed": True, "calls": 0}
    coll = store.collection(name)
    original = coll._serialize_for_write

    def _boom(_data):
        state["calls"] += 1
        if state["armed"] and state["calls"] == fail_on_call:
            state["armed"] = False
            raise exc if exc is not None else OSError("模拟磁盘写入失败")
        return original(_data)

    coll._serialize_for_write = _boom  # type: ignore[method-assign]
    return state


class BatchAtomicFailureTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")

    def test_storage_failure_at_finalize_rolls_back_entire_batch(self):
        gw = self.gateway
        cid = gw.consents.create(
            "t1", "acct-0", ["accounts:read"], 3600)["consent_id"]
        actions = [
            {"action": "create", "resource": "acct-1",
             "scopes": ["accounts:read"], "ttl_seconds": 3600},
            {"action": "authorise", "consent_id": cid},
            {"action": "revoke", "consent_id": "missing-consent"},  # 业务失败项
        ]

        # 跳过 prepare 的 claim（第 1 次暂存），在整批最终落定时（第 2 次）失败：
        # 此时业务、outbox 回调、审计都已暂存但任何正式文件都尚未被替换。
        state = _fail_once_on_collection(gw.store, "idempotency", fail_on_call=2)
        with self.assertRaises(OSError):
            gw.batch.submit("t1", "fail-tail", actions)
        assert state["calls"] >= 1

        # —— 失败后不存在任何“改了一半”的中间状态 ——
        consents = gw.store.collection("consents").list_items()
        assert [c["consent_id"] for c in consents] == [cid], consents
        assert gw.consents.get("t1", cid)["status"] == "pending", \
            "失败批次的授权必须随整批回滚，同意仍是 pending"
        assert gw.store.collection("callbacks").list_items() == [], "回调不得已登记/发送"
        idem = gw.store.collection("idempotency").get("t1|fail-tail")
        assert idem is not None and idem["status"] == "processing"
        log.info("收尾写失败后：同意数=%d（仅批外已有的 1 个，状态不变），回调=%d，幂等记录=processing",
                 len(consents), len(gw.store.collection("callbacks").list_items()))

        # —— 同 request_id 重试：接管 processing，正常完成且结果稳定 ——
        out1 = gw.batch.submit("t1", "fail-tail", actions)
        assert out1["replayed"] is False
        assert out1["summary"] == {"total": 3, "succeeded": 2, "failed": 1}
        out2 = gw.batch.submit("t1", "fail-tail", actions)
        assert out2["replayed"] is True
        assert out2["results"] == out1["results"]

        # 只新建了 1 个同意；授权只发生一次；回调只发一次
        assert len(gw.store.collection("consents").list_items()) == 2
        assert gw.consents.get("t1", cid)["status"] == "authorised"
        evt = gw.callbacks.status(f"evt-consent-{cid}")
        assert evt["attempts"] == 1 and evt["status"] == "delivered", evt
        receipts = gw.sender.list_receipts(f"evt-consent-{cid}")
        assert len(receipts) == 1, receipts
        log.info("失败后同标识重试完成：results 稳定一致，回调 attempts=1，回执=%d", len(receipts))

    def test_storage_failure_mid_batch_all_or_nothing_then_retry(self):
        """更早的存储暂存失败（consents 集合）同样整批不留痕。"""
        gw = self.gateway
        actions = [
            {"action": "create", "resource": "a", "scopes": ["s:x"],
             "ttl_seconds": 10},
            {"action": "create", "resource": "b", "scopes": ["s:y"],
             "ttl_seconds": 10},
        ]
        state = _fail_once_on_collection(gw.store, "consents")
        with self.assertRaises(OSError):
            gw.batch.submit("t1", "fail-consents", actions)
        assert state["calls"] >= 1
        assert gw.store.collection("consents").list_items() == []
        out = gw.batch.submit("t1", "fail-consents", actions)
        assert out["summary"]["succeeded"] == 2
        assert len(gw.store.collection("consents").list_items()) == 2
        # 再重放仍是首次的两个 consent_id，不产生第三、第四个
        again = gw.batch.submit("t1", "fail-consents", actions)
        assert again["replayed"] is True
        ids1 = [r["consent_id"] for r in out["results"]]
        ids2 = [r["consent_id"] for r in again["results"]]
        assert ids1 == ids2
        assert len(gw.store.collection("consents").list_items()) == 2


class ConcurrentSameRequestTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")

    def test_threads_same_request_id_all_get_first_result(self):
        gw = self.gateway
        cid = gw.consents.create(
            "t1", "acct-1", ["accounts:read"], 3600)["consent_id"]
        actions = [
            {"action": "create", "resource": "acct-2",
             "scopes": ["accounts:read"], "ttl_seconds": 100},
            {"action": "authorise", "consent_id": cid},
        ]
        n = 24
        barrier = threading.Barrier(n)
        outputs: list[dict] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def fire():
            barrier.wait()
            try:
                with lock:
                    outputs.append(gw.batch.submit("t1", "race-x", actions))
            except Exception as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=fire) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, [type(e).__name__ + ":" + str(e) for e in errors]
        assert len(outputs) == n
        first = next(o for o in outputs if not o["replayed"])
        replays = [o for o in outputs if o["replayed"]]
        assert len(replays) == n - 1
        for o in outputs:
            assert o["results"] == first["results"]
        # 唯一执行一次：只多建 1 个同意、授权 1 次、回调 1 次
        assert len(gw.store.collection("consents").list_items()) == 2
        evt = gw.callbacks.status(f"evt-consent-{cid}")
        assert evt["attempts"] == 1
        assert len(gw.sender.list_receipts(f"evt-consent-{cid}")) == 1
        log.info("%d 线程同 request_id：1 次执行 + %d 份一致重放，无 in_progress 报错",
                 n, len(replays))

    def test_http_concurrent_same_request_id_quota_charged_once(self):
        """完整 HTTP 栈：并发同单全部 200，落败重放不占配额，用量恰好为 1。"""
        from fastapi.testclient import TestClient

        gw = self.gateway
        key = self.issue_key("t1")
        actions = [
            {"action": "create", "resource": "acct-1",
             "scopes": ["accounts:read"], "ttl_seconds": 3600},
        ]
        payload = {"request_id": "http-race", "actions": actions}
        n = 16
        barrier = threading.Barrier(n)
        results: list[tuple[int, dict]] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def fire():
            # 每线程独立 TestClient，共享同一个内存 gateway（线程池外直接调用）
            client = TestClient(self.app)
            barrier.wait()
            try:
                r = client.post("/t/t1/consents/batch", json=payload,
                                headers=key["headers"])
                with lock:
                    results.append((r.status_code, r.json()))
            except Exception as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)
            finally:
                client.close()

        threads = [threading.Thread(target=fire) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, errors
        assert all(code == 200 for code, _ in results), results
        ids = {body["results"][0]["consent_id"] for _, body in results}
        assert len(ids) == 1, ids
        assert sum(1 for _, b in results if not b["replayed"]) == 1
        assert sum(1 for _, b in results if b["replayed"]) == n - 1
        assert len(gw.store.collection("consents").list_items()) == 1
        # 关键口径：并发窗口里的落败重放不重复占用限流/配额，整批只计 1 次
        usage = self.client.get(
            "/t/t1/usage", headers=key["headers"],
            params={"endpoint": "POST /consents/batch"},
        ).json()
        assert usage == {"rate": 1, "quota": 1}, usage
        # 完成后的再一次重放：仍然 0 占用
        r = self.client.post("/t/t1/consents/batch", json=payload,
                             headers=key["headers"])
        assert r.status_code == 200 and r.json()["replayed"] is True
        usage_after = self.client.get(
            "/t/t1/usage", headers=key["headers"],
            params={"endpoint": "POST /consents/batch"},
        ).json()
        assert usage_after == {"rate": 1, "quota": 1}, usage_after
        log.info("%d 并发 HTTP 同单全部 200，用量=%s（完成后重放仍为 1）", n, usage_after)

    def test_replay_after_first_completes_does_not_resend_callback(self):
        gw = self.gateway
        cid = gw.consents.create(
            "t1", "acct-1", ["accounts:read"], 3600)["consent_id"]
        actions = [{"action": "authorise", "consent_id": cid}]
        first = gw.batch.submit("t1", "cb-once", actions)
        assert not first["replayed"]
        for _ in range(5):
            rep = gw.batch.submit("t1", "cb-once", actions)
            assert rep["replayed"] is True
            assert rep["results"] == first["results"]
        evt = gw.callbacks.status(f"evt-consent-{cid}")
        assert evt["attempts"] == 1 and evt["status"] == "delivered"
        assert len(gw.sender.list_receipts(f"evt-consent-{cid}")) == 1
        log.info("5 次重放后回调仍只投递 1 次")


# ---- 跨进程：两个独立进程同时提交同一 request_id -------------------------

_PROC_SNIPPET = """
import json, sys
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
                      "replayed": out["replayed"]}))
except Exception as exc:
    print(json.dumps({"error": type(exc).__name__, "code": getattr(exc, "code", None)}))
finally:
    gw.close()
"""


class CrossProcessBatchRaceTest(unittest.TestCase):
    def test_two_processes_both_get_stable_result(self):
        tmp = tempfile.mkdtemp()
        procs = [
            subprocess.Popen(
                [sys.executable, "-c", _PROC_SNIPPET, tmp, "proc-race"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            for _ in range(2)
        ]
        outs = []
        for p in procs:
            stdout, stderr = p.communicate(timeout=60)
            assert p.returncode == 0, stderr.decode()
            outs.append(json.loads(stdout.decode().strip().splitlines()[-1]))

        log.info("跨进程并发同 request_id 结果=%s", outs)
        # 两个进程都必须成功拿到同一份首次结果：不允许任何一方收到 in_progress
        assert all("error" not in o for o in outs), outs
        ids = {o["consent_id"] for o in outs}
        assert len(ids) == 1, outs
        assert {o["replayed"] for o in outs} == {True, False}, outs

        # 落盘侧也恰好只有一个同意
        st = Settings(data_dir=tmp, default_rate_limit=1000,
                      default_rate_window_seconds=60.0, default_quota=10000,
                      default_quota_window_seconds=86400.0,
                      callback_max_attempts=3, callback_backoff_base_seconds=0.01,
                      callback_backoff_factor=2.0, max_payload_bytes=65536)
        gw = Gateway(st)
        try:
            assert len(gw.store.collection("consents").list_items()) == 1
            rec = gw.store.collection("idempotency").get("t1|proc-race")
            assert rec["status"] == "completed" and rec["results"] is not None
        finally:
            gw.close()


if __name__ == "__main__":
    unittest.main()
