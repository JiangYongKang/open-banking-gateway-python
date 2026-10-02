"""并发竞争补强：

* 同一变更单并发批准：版本只推进一次、旧版本链只有一条；
* 批准与撤销并发撞车：要么“已批准后撤销”要么“撤销后批准被拒”，结果明确可解释，
  绝不出现撤销后新作用域仍可用；
* 跨进程（multiprocessing）同一 request_id 并发批量提交：只执行一次。
"""
from __future__ import annotations

import logging
import threading
import unittest

from app.errors import ConsentAmendmentVoidError
from tests.support import GatewayTestCase

log = logging.getLogger("test.amendment_races")


class AmendmentConcurrencyTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")

    def _authorised_consent(self):
        cid = self.gateway.consents.create(
            "t1", "acct-1", ["accounts:read"], 3600)["consent_id"]
        self.gateway.consents.authorise("t1", cid)
        return cid

    def test_concurrent_approve_single_effect(self):
        gw = self.gateway
        cid = self._authorised_consent()
        aid = gw.amendments.request(
            "t1", cid, add_scopes=["payments:write"])["amendment_id"]
        barrier = threading.Barrier(12)
        ok = {"approved": 0, "void": 0, "other": 0}
        lock = threading.Lock()

        def approve():
            barrier.wait()
            try:
                gw.amendments.approve("t1", aid)
                with lock:
                    ok["approved"] += 1
            except ConsentAmendmentVoidError:
                with lock:
                    ok["void"] += 1
            except Exception:  # noqa: BLE001
                with lock:
                    ok["other"] += 1

        threads = [threading.Thread(target=approve) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        rec = gw.consents.get("t1", cid)
        # 批准幂等：重复批准返回当前态不算错误；版本只 +1 一次，旧版本仅一条
        assert ok["void"] == 0 and ok["other"] == 0, ok
        assert rec["version"] == 3, rec["version"]
        assert len(rec["versions"]) == 1
        assert rec["scopes"] == ["accounts:read", "payments:write"]
        log.info("12 并发批准：版本=%d 旧版本链=%d scopes=%s",
                 rec["version"], len(rec["versions"]), rec["scopes"])

    def test_concurrent_approve_vs_revoke_explainable(self):
        gw = self.gateway
        outcomes = {"approved_then_revoked": 0, "revoked_then_approve_rejected": 0,
                    "surprised": 0}
        lock = threading.Lock()
        for trial in range(20):
            cid = self._authorised_consent()
            aid = gw.amendments.request(
                "t1", cid, add_scopes=[f"s:{trial}"])["amendment_id"]
            start = threading.Barrier(2)
            results = {}

            def do_approve():
                start.wait()
                try:
                    gw.amendments.approve("t1", aid)
                    results["approve"] = "ok"
                except ConsentAmendmentVoidError:
                    results["approve"] = "void"
                except Exception as exc:  # noqa: BLE001
                    results["approve"] = type(exc).__name__

            def do_revoke():
                start.wait()
                try:
                    gw.consents.revoke("t1", cid)
                    results["revoke"] = "ok"
                except Exception as exc:  # noqa: BLE001
                    results["revoke"] = type(exc).__name__

            t1 = threading.Thread(target=do_approve)
            t2 = threading.Thread(target=do_revoke)
            t1.start(); t2.start(); t1.join(); t2.join()

            rec = gw.consents.get("t1", cid)
            am = gw.amendments.get("t1", aid)
            # 最终态必为 revoked
            assert rec["status"] == "revoked", (trial, rec["status"])
            if am["status"] == "void" and results["approve"] == "void":
                with lock:
                    outcomes["revoked_then_approve_rejected"] += 1
            elif am["status"] == "approved" and results["approve"] == "ok":
                with lock:
                    outcomes["approved_then_revoked"] += 1
            else:
                with lock:
                    outcomes["surprised"] += 1
            # 无论谁赢：撤销后访问必须被拒，新作用域也不可用
            try:
                gw.consents.check_access("t1", cid, "acct-1", f"s:{trial}")
                raise AssertionError("撤销后新作用域仍可用，违反不变量")
            except Exception as exc:
                assert exc.code == "consent_revoked", exc.code
        assert outcomes["surprised"] == 0, outcomes
        log.info("20 轮批准/撤销撞车：先批准后撤销=%d 先撤销后拒批=%d",
                 outcomes["approved_then_revoked"],
                 outcomes["revoked_then_approve_rejected"])


# ---- 跨进程幂等 ---------------------------------------------------------

# 独立进程执行的提交脚本：参数为 data_dir/request_id，输出一行 JSON 结果。
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


class CrossProcessIdempotencyTest(unittest.TestCase):
    def test_two_processes_same_request_id_single_execution(self):
        import json
        import subprocess
        import sys
        import tempfile

        tmp = tempfile.mkdtemp()
        procs = [
            subprocess.Popen(
                [sys.executable, "-c", _PROC_SNIPPET, tmp, "proc-shared"],
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
        ids = {o.get("consent_id") for o in outs if o.get("consent_id")}
        assert len(ids) == 1, outs
        fresh = [o for o in outs if o.get("replayed") is False]
        replays = [o for o in outs if o.get("replayed") is True]
        # 新语义：落败方不再收到 idempotency_in_progress，而是等待首事务提交后
        # 直接拿到与首次完全一致的结果
        assert len(fresh) == 1 and len(replays) == 1, outs
        assert all("error" not in o for o in outs), outs
        assert {o["consent_id"] for o in replays} == ids


if __name__ == "__main__":
    unittest.main()
