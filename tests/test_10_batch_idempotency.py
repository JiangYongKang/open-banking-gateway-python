"""批量同意动作 + 请求级幂等：

* 混合动作逐项独立结果；非法项失败不影响其它项、不留半状态；
* 同 request_id 重放返回完全一致结果，不重复扣额度/发回调/改状态；
* 同 request_id 不同内容 -> idempotency_conflict；
* 并发提交同一批只执行一次（创建只产生一个同意、回调只发一次）；
* request_id 作用域按租户隔离。
"""
from __future__ import annotations

import logging
import threading
import unittest

from app.errors import IdempotencyConflictError
from tests.support import GatewayTestCase

log = logging.getLogger("test.batch")


class BatchServiceTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")

    def test_mixed_actions_partial_failure_no_residue(self):
        gw = self.gateway
        actions = [
            {"action": "create", "resource": "acct-1", "scopes": ["accounts:read"],
             "ttl_seconds": 3600},
            {"action": "create", "resource": "acct-2", "scopes": ["payments:write"],
             "ttl_seconds": 600},
            {"action": "revoke", "consent_id": "consent-missing"},  # 非法项
            {"action": "weird"},  # 未知动作
        ]
        out = gw.batch.submit("t1", "req-1", actions)
        assert out["summary"] == {"total": 4, "succeeded": 2, "failed": 2}, out["summary"]
        codes = [(r["ok"], r.get("error", {}).get("code")) for r in out["results"]]
        assert codes[0][0] and codes[1][0]
        assert codes[1][0]  # 第二项成功：未被第三项拖累
        assert codes[2] == (False, "consent_not_found")
        assert codes[3] == (False, "validation_error")
        # 前两项真实落库且状态正确（PENDING）
        cid = out["results"][0]["consent_id"]
        rec = gw.consents.get("t1", cid)
        assert rec["status"] == "pending"
        consents = gw.store.collection("consents").list_items()
        assert len(consents) == 2  # 失败项没有留下任何半成品
        log.info("部分失败结果=%s；落库同意数=%d（无残留）", codes, len(consents))

    def test_replay_returns_identical_result_and_has_no_side_effects(self):
        gw = self.gateway
        cid = gw.consents.create("t1", "acct-1", ["accounts:read"], 3600)["consent_id"]
        actions = [
            {"action": "authorise", "consent_id": cid},
            {"action": "revoke", "consent_id": "consent-missing"},
        ]
        first = gw.batch.submit("t1", "dup-1", actions)
        versions = gw.consents.get("t1", cid)["version"]
        cb_before = gw.callbacks.status(f"evt-consent-{cid}")["attempts"]

        second = gw.batch.submit("t1", "dup-1", actions)
        assert second["replayed"] is True
        assert second["results"] == first["results"]
        # 没有重复改状态 / 重复发回调
        assert gw.consents.get("t1", cid)["version"] == versions
        assert gw.callbacks.status(f"evt-consent-{cid}")["attempts"] == cb_before == 1
        log.info("重放结果一致；回调 attempts=%d，同意版本不变", cb_before)

    def test_same_request_id_different_payload_conflicts(self):
        gw = self.gateway
        gw.batch.submit("t1", "k", [
            {"action": "create", "resource": "a", "scopes": ["s:x"], "ttl_seconds": 10}
        ])
        with self.assertRaises(IdempotencyConflictError):
            gw.batch.submit("t1", "k", [
                {"action": "create", "resource": "b", "scopes": ["s:y"], "ttl_seconds": 10}
            ])

    def test_concurrent_same_batch_executed_once(self):
        gw = self.gateway
        actions = [
            {"action": "create", "resource": "acct-1", "scopes": ["accounts:read"],
             "ttl_seconds": 100},
        ]
        barrier = threading.Barrier(16)
        outputs: list[dict] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def fire():
            barrier.wait()
            try:
                out = gw.batch.submit("t1", "race-1", actions)
                with lock:
                    outputs.append(out)
            except Exception as exc:  # noqa: BLE001
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=fire) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, errors
        ids = {o["results"][0]["consent_id"] for o in outputs}
        assert len(ids) == 1, ids
        assert len(outputs) == 16
        assert sum(1 for o in outputs if not o["replayed"]) == 1
        assert sum(1 for o in outputs if o["replayed"]) == 15
        # 只创建了一个同意
        assert len(gw.store.collection("consents").list_items()) == 1
        log.info("16 并发同批：唯一执行 1 次，15 次拿到稳定重放结果")

    def test_concurrent_amendment_in_batch_single_effect(self):
        gw = self.gateway
        cid = gw.consents.create("t1", "acct-1", ["accounts:read"], 3600)["consent_id"]
        gw.consents.authorise("t1", cid)
        actions = [{"action": "amend_request", "consent_id": cid,
                    "add_scopes": ["pay:write"]}]
        barrier = threading.Barrier(10)
        outs: list = []
        errs: list = []

        def fire():
            barrier.wait()
            try:
                outs.append(gw.batch.submit("t1", "amend-race", actions))
            except Exception as exc:  # noqa: BLE001
                errs.append(exc)

        threads = [threading.Thread(target=fire) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errs, errs
        # 只有一次真正提交；其余全部是同一结果的重放（同一个 amendment_id）
        amendment_ids = {o["results"][0].get("amendment_id") for o in outs}
        assert len(amendment_ids) == 1, amendment_ids
        pending = [a for a in gw.store.collection("amendments").list_items()]
        assert len(pending) == 1
        log.info("并发变更申请只产生 1 个变更单")

    def test_revoke_then_amend_in_same_batch_item_fails_cleanly(self):
        # 已撤销同意再做变更：单项失败且错误码明确，其它项不受影响
        gw = self.gateway
        cid = gw.consents.create("t1", "acct-1", ["accounts:read"], 3600)["consent_id"]
        gw.consents.authorise("t1", cid)
        gw.consents.revoke("t1", cid)
        other = gw.consents.create("t1", "acct-2", ["accounts:read"], 100)["consent_id"]
        out = gw.batch.submit("t1", "mix", [
            {"action": "amend_request", "consent_id": cid, "add_scopes": ["x:y"]},
            {"action": "authorise", "consent_id": other},
        ])
        assert out["results"][0]["ok"] is False
        assert out["results"][0]["error"]["code"] == "consent_amendment_conflict"
        assert out["results"][1]["ok"] is True
        assert gw.consents.get("t1", other)["status"] == "authorised"
        assert gw.store.collection("amendments").list_items() == []

    def test_request_id_scoped_by_tenant(self):
        gw = self.gateway
        self.register("t2")
        actions = [{"action": "create", "resource": "a", "scopes": ["s:x"],
                    "ttl_seconds": 10}]
        o1 = gw.batch.submit("t1", "shared-id", actions)
        o2 = gw.batch.submit("t2", "shared-id", actions)
        assert not o1["replayed"] and not o2["replayed"]
        assert o1["results"][0]["consent_id"] != o2["results"][0]["consent_id"]


class BatchHttpTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")
        self.key = self.issue_key("t1")
        self.h = self.key["headers"]

    def test_batch_endpoint_replay_does_not_consume_quota(self):
        payload = {"request_id": "http-1", "actions": [
            {"action": "create", "resource": "acct-1", "scopes": ["accounts:read"],
             "ttl_seconds": 3600},
            {"action": "create", "resource": "acct-2", "scopes": ["accounts:read"],
             "ttl_seconds": 3600},
        ]}
        r1 = self.client.post("/t/t1/consents/batch", json=payload, headers=self.h)
        assert r1.status_code == 200 and not r1.json()["replayed"]
        r2 = self.client.post("/t/t1/consents/batch", json=payload, headers=self.h)
        assert r2.status_code == 200 and r2.json()["replayed"] is True
        # 整批只占 1 次（不是按动作条数），重放占 0 次
        usage = self.client.get("/t/t1/usage", headers=self.h,
                                params={"endpoint": "POST /consents/batch"}).json()
        assert usage == {"rate": 1, "quota": 1}, usage
        log.info("批量端点用量=%s（整批 1 次，重放 0 次）", usage)

    def test_batch_endpoint_requires_scope(self):
        weak = self.issue_key("t1", scopes=["accounts:read"])
        r = self.client.post("/t/t1/consents/batch", headers=weak["headers"],
                             json={"request_id": "x", "actions": [
                                 {"action": "create", "resource": "a",
                                  "scopes": ["s"], "ttl_seconds": 1}]})
        assert r.status_code == 403 and r.json()["error"]["code"] == "scope_insufficient"


if __name__ == "__main__":
    unittest.main()
