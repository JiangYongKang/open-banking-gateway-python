"""批量同意动作 + 请求级幂等，以及合作方自助只读视图。

验收重点：
* 批量混合动作逐条出结果，部分失败不留半更新残留；
* 同 Idempotency-Key 重放结果稳定，不重复改状态/扣额度/发回调；
* 并发下同一批/同一变更只执行一次；
* 自助视图严格不跨租户（他人同意等同不存在），且只读、不影响用量口径。
"""
from __future__ import annotations

import logging
import threading

from tests.support import GatewayTestCase

log = logging.getLogger("test.batch_views")


class BatchIdempotencyTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")
        self.key = self.issue_key(
            "t1", scopes=["accounts:read", "consents:write", "consents:read"]
        )
        self.h = self.key["headers"]

    def _batch(self, actions, key="req-1", expect_http=200):
        r = self.client.post(
            "/t/t1/consent-actions/batch",
            headers={**self.h, "Idempotency-Key": key},
            json={"actions": actions},
        )
        assert r.status_code == expect_http, r.text
        return r.json()

    def test_mixed_batch_partial_failure_leaves_no_residue(self):
        body = self._batch([
            {"action": "create", "resource": "acct-1",
             "scopes": ["accounts:read"], "ttl_seconds": 3600},
            {"action": "authorise", "consent_id": "consent-missing"},
        ])
        results = body["results"]
        assert results[0]["ok"] is True
        assert results[0]["action"] == "create"
        cid = results[0]["consent_id"]
        assert results[1]["ok"] is False
        assert results[1]["error"]["code"] == "consent_not_found"
        # 合法条目已落地，失败条目没有制造任何同意
        rec = self.gateway.consents.get("t1", cid)
        assert rec["status"] == "pending"
        assert self.gateway.store.collection("consents").get("consent-missing") is None

    def test_full_mixed_lifecycle_in_one_batch(self):
        # 创建 + 授权在同批（按顺序执行，授权能拿到刚创建的 id 需要引用，
        # 因此这里分两步：先 create 批，再 authorise/revoke/amend 混合批）
        b1 = self._batch([
            {"action": "create", "resource": "a", "scopes": ["accounts:read"],
             "ttl_seconds": 3600},
            {"action": "create", "resource": "b", "scopes": ["accounts:read"],
             "ttl_seconds": 100},
        ], key="create-two")
        cid_a = b1["results"][0]["consent_id"]
        cid_b = b1["results"][1]["consent_id"]

        b2 = self._batch([
            {"action": "authorise", "consent_id": cid_a},
            {"action": "authorise", "consent_id": cid_b},
            # 对 b 申请变更（合法）
            {"action": "request_amendment", "consent_id": cid_b,
             "add_scopes": ["x:y"], "extend_ttl_seconds": 50},
            # 再次授权 a：非法状态流转 -> 该条失败
            {"action": "authorise", "consent_id": cid_a},
        ], key="auth-and-amend")
        oks = [r["ok"] for r in b2["results"]]
        assert oks == [True, True, True, False], oks
        assert b2["results"][3]["error"]["code"] == "consent_invalid_transition"
        # 失败条目不影响前面已落地条目
        assert self.gateway.consents.get("t1", cid_a)["status"] == "authorised"
        amd = self.gateway.consents.list_amendments("t1", cid_b)[0]
        assert amd["status"] == "pending"
        assert amd["add_scopes"] == ["x:y"]

    def test_replay_returns_stable_result_and_no_duplicate_side_effects(self):
        actions = [
            {"action": "create", "resource": "acct-1",
             "scopes": ["accounts:read"], "ttl_seconds": 3600},
        ]
        first = self._batch(actions, key="stable-key")
        cid = first["results"][0]["consent_id"]
        # 统计回调投递次数（authorise 批里会触发；这里用 revoke 批验证更直接）
        fired = {"n": 0}
        orig = self.gateway.callbacks._sender

        def counting(rec):
            fired["n"] += 1
            return orig(rec)

        self.gateway.callbacks._sender = counting
        revoke_actions = [{"action": "revoke", "consent_id": cid}]
        r1 = self._batch(revoke_actions, key="revoke-key")
        n_after_first = fired["n"]
        assert r1["results"][0]["ok"] is True
        # 多次重放
        for _ in range(5):
            r = self._batch(revoke_actions, key="revoke-key")
            assert r["replayed"] is True
            assert r["results"][0]["consent_id"] == cid
        assert fired["n"] == n_after_first, "重放不得重复触发回调"
        # 同意只被撤销一次：history 长度固定（create + revoke，未单独授权）
        rec = self.gateway.consents.get("t1", cid)
        assert rec["status"] == "revoked"
        assert len(rec["history"]) == 2
        # 重复撤销本身非法，但重放不重新执行，结果仍是首次成功结果
        assert r1["results"][0]["ok"] is True
        log.info("5 次重放: 回调只发 %d 次, history=%d", fired["n"], len(rec["history"]))

    def test_replay_does_not_consent_quota_twice(self):
        # 限流配额设小：首次占 1，重放不应再占
        self.gateway.settings  # noqa
        from app.ratelimit import LimitConfig

        lim = LimitConfig(rate_limit=5, rate_window=60.0, quota=5, quota_window=60.0)
        actions = [{"action": "create", "resource": "r",
                    "scopes": ["accounts:read"], "ttl_seconds": 10}]
        self._batch(actions, key="quota-key")
        for _ in range(10):
            self._batch(actions, key="quota-key")  # 全部重放
        usage = self.gateway.limiter.usage(
            "t1", "POST /consent-actions/batch", lim
        )
        # 只有首次真正占额度；重放命中幂等直接返回，不重复计数
        assert usage["rate"] == 1, usage
        assert usage["quota"] == 1, usage

    def test_same_key_different_body_conflicts(self):
        self._batch([{"action": "create", "resource": "r",
                      "scopes": ["accounts:read"], "ttl_seconds": 10}], key="k")
        r = self.client.post(
            "/t/t1/consent-actions/batch",
            headers={**self.h, "Idempotency-Key": "k"},
            json={"actions": [{"action": "create", "resource": "other",
                               "scopes": ["accounts:read"], "ttl_seconds": 10}]},
        )
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "idempotency_replay_mismatch"

    def test_numeric_equivalence_is_same_request(self):
        actions = [{"action": "create", "resource": "r",
                    "scopes": ["accounts:read"], "ttl_seconds": 10}]
        first = self._batch(actions, key="num-key")
        # JSON 里 10 vs 10.0 语义相同，应视为同一请求
        again = self._batch(
            [{"action": "create", "resource": "r",
              "scopes": ["accounts:read"], "ttl_seconds": 10.0}],
            key="num-key",
        )
        assert again["replayed"] is True
        assert again["results"][0]["consent_id"] == first["results"][0]["consent_id"]

    def test_empty_and_unknown_action_rejected_as_batch(self):
        # 整批形态非法 -> 400，且不产生任何条目
        r = self.client.post(
            "/t/t1/consent-actions/batch",
            headers={**self.h, "Idempotency-Key": "bad"},
            json={"actions": []},
        )
        assert r.status_code == 400
        r = self.client.post(
            "/t/t1/consent-actions/batch",
            headers={**self.h, "Idempotency-Key": "bad2"},
            json={"actions": [{"action": "teleport"}]},
        )
        assert r.status_code == 400 and r.json()["error"]["code"] == "batch_request_invalid"
        assert self.gateway.store.collection("consents").list_items() == []

    def test_idempotency_key_scoped_per_tenant(self):
        # t2 用同名 key 应是独立的首次执行
        self.register("t2")
        key2 = self.issue_key(
            "t2", scopes=["accounts:read", "consents:write"]
        )
        payload = {"actions": [{"action": "create", "resource": "r",
                                "scopes": ["accounts:read"], "ttl_seconds": 10}]}
        r1 = self.client.post(
            "/t/t1/consent-actions/batch",
            headers={**self.h, "Idempotency-Key": "shared"}, json=payload)
        r2 = self.client.post(
            "/t/t2/consent-actions/batch",
            headers={**key2["headers"], "Idempotency-Key": "shared"}, json=payload)
        assert r1.json()["replayed"] is False
        assert r2.json()["replayed"] is False
        assert r1.json()["results"][0]["consent"] ["tenant_id"] == "t1"
        assert r2.json()["results"][0]["consent"]["tenant_id"] == "t2"


class BatchConcurrencyTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")

    def test_concurrent_same_batch_executes_once(self):
        gw = self.gateway
        results = []
        lock = threading.Lock()
        barrier = threading.Barrier(16)
        actions = [{"action": "create", "resource": "r",
                    "scopes": ["accounts:read"], "ttl_seconds": 10}]

        def fire():
            barrier.wait()
            try:
                out = gw.batch.execute("t1", "concurrent-key", actions)
                with lock:
                    results.append(out)
            except Exception as e:  # noqa: BLE001
                with lock:
                    results.append(e)

        threads = [threading.Thread(target=fire) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(results) == 16
        assert all(not isinstance(r, Exception) for r in results), results
        cids = {r["results"][0]["consent_id"] for r in results}
        assert len(cids) == 1, cids  # 全部拿到同一个首次结果
        firsts = [r for r in results if not r["replayed"]]
        assert len(firsts) == 1
        # 只真正创建了一条同意
        consents = gw.store.collection("consents").list_items()
        assert len(consents) == 1
        log.info("16 并发同一批次: 首次执行=1, 重放=15, consent 数=%d", len(consents))

    def test_concurrent_amendment_requests_single_winner(self):
        from app.errors import ConsentAmendmentPendingError

        gw = self.gateway
        cid = gw.consents.create(
            "t1", "acct-1", ["accounts:read"], 3600
        )["consent_id"]
        gw.consents.authorise("t1", cid)
        ok = {"n": 0}
        rejected = {"n": 0}
        lock = threading.Lock()
        barrier = threading.Barrier(12)

        def request():
            barrier.wait()
            try:
                gw.consents.request_amendment("t1", cid, extend_ttl_seconds=60)
                with lock:
                    ok["n"] += 1
            except ConsentAmendmentPendingError:
                with lock:
                    rejected["n"] += 1

        threads = [threading.Thread(target=request) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert ok["n"] == 1, (ok, rejected)
        assert rejected["n"] == 11
        rec = gw.consents.get("t1", cid)
        pending = [a for a in rec["amendments"] if a["status"] == "pending"]
        assert len(pending) == 1
        log.info("12 并发变更申请: 成功=1 拒绝=11 待生效变更=1")


class SelfServiceViewTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")
        self.register("t2")
        self.key1 = self.issue_key(
            "t1", scopes=["accounts:read", "consents:write", "consents:read"]
        )
        self.key2 = self.issue_key("t2", scopes=["consents:read"])
        self.now = 1_000_000.0

    def _consent_with_traffic(self):
        cid = self.create_authorised_consent("t1", "acct-1", ["accounts:read"], 3600)
        h = self.key1["headers"]
        # 一次放行 + 一次资源不符拒绝 + 一次作用域拒绝（用别的同意触发 scope 拒绝更难，
        # 这里制造一次资源不符即可，再撤销制造 revoked 拒绝）
        self.client.get(f"/t/t1/accounts/acct-1", params={"consent_id": cid}, headers=h)
        self.client.get(f"/t/t1/accounts/other", params={"consent_id": cid}, headers=h)
        return cid

    def test_access_results_show_allowed_and_denials(self):
        cid = self._consent_with_traffic()
        r = self.client.get(
            f"/t/t1/consents/{cid}/access-results", headers=self.key1["headers"]
        )
        assert r.status_code == 200, r.text
        data = r.json()
        results = {(x["result"], x.get("reason")) for x in data["access_results"]}
        assert ("allowed", None) in results
        assert ("denied", "consent_resource_mismatch") in results
        log.info("访问结果视图: %s", results)

    def test_callbacks_view_lists_related_deliveries(self):
        cid = self._consent_with_traffic()  # authorise 已触发 evt-consent-{cid}
        r = self.client.get(
            f"/t/t1/consents/{cid}/callbacks", headers=self.key1["headers"]
        )
        assert r.status_code == 200, r.text
        types = [c["event_type"] for c in r.json()["callbacks"]]
        assert "consent.authorised" in types
        # 每条带投递状态与尝试日志
        for c in r.json()["callbacks"]:
            assert c["status"] in ("delivered", "pending", "failed")
            assert isinstance(c["attempt_log"], list)

    def test_overview_combines_state_access_and_callbacks(self):
        cid = self._consent_with_traffic()
        r = self.client.get(f"/t/t1/consents/{cid}/view",
                            headers=self.key1["headers"])
        assert r.status_code == 200, r.text
        v = r.json()
        assert v["status"] == "authorised"
        assert v["resource"] == "acct-1"
        assert len(v["access_results"]) >= 2
        assert any(c["event_type"] == "consent.authorised" for c in v["callbacks"])

    def test_view_strict_tenant_isolation(self):
        cid = self._consent_with_traffic()
        # t2 查 t1 的同意：与不存在完全同形
        for suffix in ("view", "access-results", "callbacks"):
            r = self.client.get(
                f"/t/t2/consents/{cid}/{suffix}", headers=self.key2["headers"]
            )
            assert r.status_code == 404, (suffix, r.text)
            assert r.json()["error"]["code"] == "consent_not_found"

    def test_views_are_read_only_and_do_not_move_usage(self):
        from app.ratelimit import LimitConfig

        cid = self._consent_with_traffic()
        lim = LimitConfig(rate_limit=100, rate_window=60.0,
                          quota=100, quota_window=60.0)
        before = self.gateway.limiter.usage("t1", "GET /accounts/{id}", lim)
        # 只统计业务审计（同意/资源/回调/批量），认证层的 api_key_auth 属既有安全日志
        business_actions = {
            "consent_access", "resource_access", "consent_batch",
            "consent_create", "consent_authorise", "consent_revoke",
            "consent_amendment_request", "consent_amendment_approve",
            "consent_amendment_reject", "consent_amendment_void",
        }

        def _business_audit():
            return [
                e for e in self.gateway.audit.list("t1")
                if e["action"] in business_actions
            ]

        business_before = len(_business_audit())
        for _ in range(5):
            for suffix in ("view", "access-results", "callbacks"):
                r = self.client.get(
                    f"/t/t1/consents/{cid}/{suffix}", headers=self.key1["headers"]
                )
                assert r.status_code == 200
        after = self.gateway.limiter.usage("t1", "GET /accounts/{id}", lim)
        business_after = len(_business_audit())
        # 业务接口用量不被视图查询影响
        assert after == before, (before, after)
        # 视图本身不产生任何业务审计（零业务副作用）
        assert business_after == business_before
        log.info("15 次只读视图查询: 业务用量不变=%s 业务审计条数不变=%d",
                 after, business_after)

    def test_missing_scope_rejected(self):
        cid = self._consent_with_traffic()
        # 只有 accounts:read 的 key 不能读自助视图
        plain = self.issue_key("t1", scopes=["accounts:read"])
        r = self.client.get(f"/t/t1/consents/{cid}/view", headers=plain["headers"])
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "scope_insufficient"


if __name__ == "__main__":
    import unittest

    unittest.main()


class AmendmentCollisionExplainTest(GatewayTestCase):
    """变更与撤销/到期/批准撞在一起时，结果必须明确可解释（状态+审计原因）。"""

    def setUp(self):
        super().setUp()
        self.register("t1")

    def test_amendment_approve_then_revoke_explained(self):
        from app.errors import ConsentAmendmentNotPendingError

        gw = self.gateway
        cid = gw.consents.create("t1", "a", ["accounts:read"], 3600)["consent_id"]
        gw.consents.authorise("t1", cid)
        out = gw.consents.request_amendment("t1", cid, extend_ttl_seconds=100)
        aid = out["amendment"]["amendment_id"]
        gw.consents.approve_amendment("t1", cid, aid)
        # 已批准的变更不能再批一次
        try:
            gw.consents.approve_amendment("t1", cid, aid)
            assert False
        except ConsentAmendmentNotPendingError as e:
            assert "approved" in e.message
        rec = gw.consents.get("t1", cid)
        # 审计/历史能解释每一步
        actions = [h["action"] for h in rec["history"]]
        assert "consent_amendment_approve" in actions
        assert [a["status"] for a in rec["amendments"]] == ["approved"]

    def test_amendment_voided_by_expiry_is_explained_in_history(self):
        gw = self.gateway
        self.now = 1000.0
        gw._clock = lambda: self.now
        gw.consents._clock = gw._clock
        gw.audit._clock = gw._clock
        cid = gw.consents.create("t1", "a", ["accounts:read"], 100)["consent_id"]
        gw.consents.authorise("t1", cid)
        out = gw.consents.request_amendment("t1", cid, add_scopes=["x:y"],
                                            extend_ttl_seconds=999)
        aid = out["amendment"]["amendment_id"]
        self.now = 1200.0
        gw.consents.expire_due(now=self.now)
        rec = gw.consents.get("t1", cid)
        assert rec["status"] == "expired"
        # 作废事件带明确 reason，解释“因到期作废”
        void_events = [h for h in rec["history"]
                       if h["action"] == "consent_amendment_void"]
        assert void_events and void_events[0]["reason"] == "consent_expired"
        amd = [a for a in rec["amendments"] if a["amendment_id"] == aid][0]
        assert amd["status"] == "voided"
        assert amd["decide_history"][-1]["reason"] == "consent_expired"


class BatchAtomicityTest(GatewayTestCase):
    """整批状态/审计/幂等记录在同一事务：提交阶段失败则全部不留。"""

    def setUp(self):
        super().setUp()
        self.register("t1")

    def test_stage_failure_leaves_no_state_and_no_idempotency(self):
        gw = self.gateway
        consents_coll = gw.store.collection("consents")
        orig = consents_coll._serialize_for_write
        calls = {"n": 0}

        def flaky(data):
            calls["n"] += 1
            if calls["n"] >= 1:
                raise OSError("模拟磁盘故障")

        actions = [
            {"action": "create", "resource": "a", "scopes": ["accounts:read"],
             "ttl_seconds": 10},
            {"action": "create", "resource": "b", "scopes": ["accounts:read"],
             "ttl_seconds": 10},
        ]
        try:
            consents_coll._serialize_for_write = flaky
            try:
                gw.batch.execute("t1", "atomic-key", actions)
                assert False, "磁盘故障必须让整批失败"
            except OSError:
                pass
        finally:
            consents_coll._serialize_for_write = orig
        # 三个集合都没有留下本批痕迹
        assert gw.store.collection("consents").list_items() == []
        assert gw.store.collection("idempotency").list_items() == []
        audit_entries = [e for e in gw.audit.list("t1")
                         if e["action"] == "consent_batch"]
        assert audit_entries == []
        # 故障后同键可作为全新请求重试并成功（没有被半成品幂等记录挡住）
        out = gw.batch.execute("t1", "atomic-key", actions)
        assert out["replayed"] is False
        assert len(gw.store.collection("consents").list_items()) == 2
        log.info("提交阶段磁盘故障: 0 残留；同键重试成功")

    def test_idempotency_record_stores_fingerprint_and_first_response(self):
        gw = self.gateway
        actions = [{"action": "create", "resource": "a",
                    "scopes": ["accounts:read"], "ttl_seconds": 10}]
        out = gw.batch.execute("t1", "fp-key", actions)
        rec = gw.store.collection("idempotency").get("t1|fp-key")
        assert rec is not None
        assert rec["tenant_id"] == "t1"
        assert rec["response"]["results"][0]["consent_id"] == \
            out["results"][0]["consent_id"]
        assert "fingerprint" in rec and rec["fingerprint"]
