"""合作方自助只读视图：

* 近期访问：放行列 + 各类拒绝原因；
* 关联回调投递情况；
* 严格租户隔离：访问他人同意与不存在同形（consent_not_found / 404）；
* 纯只读：不写审计、不影响业务用量口径。
"""
from __future__ import annotations

import logging
import unittest

from tests.support import GatewayTestCase

log = logging.getLogger("test.insights")


class ConsentInsightTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")
        self.register("t2")
        self.key = self.issue_key("t1")
        self.cid = self.create_authorised_consent("t1", "acct-1", ["accounts:read"])
        # 一条放行
        r = self.client.get("/t/t1/accounts/acct-1", params={"consent_id": self.cid},
                            headers=self.key["headers"])
        assert r.status_code == 200

    def test_recent_access_shows_allowed_and_deny_reasons(self):
        # 撤销后再访问 -> revoked
        self.client.post(f"/admin/tenants/t1/consents/{self.cid}/revoke",
                         headers=self.admin)
        self.client.get("/t/t1/accounts/acct-1", params={"consent_id": self.cid},
                        headers=self.key["headers"])
        ins = self.gateway.insights.consent_insight("t1", self.cid)
        recent = ins["recent_access"]
        assert recent[0]["outcome"] == "denied" and recent[0]["reason"] == "revoked"
        assert any(r["outcome"] == "allowed" for r in recent)
        assert ins["consent"]["status"] == "revoked"
        log.info("近期访问结论=%s", [(r["outcome"], r["reason"]) for r in recent])

    def test_deny_reasons_breakdown(self):
        # 另造不同拒绝原因：资源不符 / 作用域不足 / 未授权 / 到期
        cid_mismatch = self.create_authorised_consent("t1", "acct-2", ["accounts:read"])
        self.client.get("/t/t1/accounts/acct-1", params={"consent_id": cid_mismatch},
                        headers=self.key["headers"])  # resource_mismatch
        cid_pending = self.gateway.consents.create(
            "t1", "acct-3", ["accounts:read"], 3600)["consent_id"]
        self.client.get("/t/t1/accounts/acct-3", params={"consent_id": cid_pending},
                        headers=self.key["headers"])  # not_authorised
        cid_exp = self.create_authorised_consent("t1", "acct-4", ["accounts:read"], ttl=10)
        self.gateway.consents.expire_due(now=self.now + 100)
        self.client.get("/t/t1/accounts/acct-4", params={"consent_id": cid_exp},
                        headers=self.key["headers"])  # expired

        for cid, reason in [
            (cid_mismatch, "resource_mismatch"),
            (cid_pending, "not_authorised"),
            (cid_exp, "expired"),
        ]:
            ins = self.gateway.insights.consent_insight("t1", cid)
            top = ins["recent_access"][0]
            assert top["outcome"] == "denied" and top["reason"] == reason, (cid, top)
            log.info("同意 %s 拒绝原因=%s", cid, reason)

    def test_callbacks_listed(self):
        ins = self.gateway.insights.consent_insight("t1", self.cid)
        types = {cb["event_type"] for cb in ins["callbacks"]}
        assert "consent.authorised" in types, types
        assert all(cb["status"] in ("delivered", "pending", "failed")
                   for cb in ins["callbacks"])

    def test_strict_tenant_isolation_service(self):
        # t2 查 t1 的同意：与不存在同形
        with self.assertRaises(Exception) as cm:
            self.gateway.insights.consent_insight("t2", self.cid)
        assert cm.exception.code == "consent_not_found"
        # t2 查一个真的不存在的同意：同样错误，响应不可区分
        with self.assertRaises(Exception) as cm2:
            self.gateway.insights.consent_insight("t2", "consent-ghost")
        assert cm2.exception.code == "consent_not_found"
        log.info("跨租户访问与不存在同形处理")

    def test_strict_tenant_isolation_http(self):
        key2 = self.issue_key("t2", scopes=["consents:read"])
        r = self.client.get(f"/t/t2/consents/{self.cid}/insight", headers=key2["headers"])
        assert r.status_code == 404
        assert r.json()["error"]["code"] == "consent_not_found"
        # 路径/凭证租户不一致 -> 401
        r2 = self.client.get(f"/t/t2/consents/{self.cid}/insight",
                             headers=self.key["headers"])
        assert r2.status_code == 401
        # 缺作用域 -> 403
        weak = self.issue_key("t1", scopes=["accounts:read"])
        r3 = self.client.get(f"/t/t1/consents/{self.cid}/insight", headers=weak["headers"])
        assert r3.status_code == 403

    def test_insight_is_read_only_for_usage_and_audit(self):
        audit_before = len(self.gateway.audit.list("t1"))
        usage_endpoint = "GET /accounts/{id}"
        u_before = self.gateway.limiter.usage(
            "t1", usage_endpoint, self.gateway.default_limits())["rate"]
        for _ in range(5):
            self.gateway.insights.consent_insight("t1", self.cid)
        u_after = self.gateway.limiter.usage(
            "t1", usage_endpoint, self.gateway.default_limits())["rate"]
        audit_after = len(self.gateway.audit.list("t1"))
        assert u_after == u_before, (u_before, u_after)
        assert audit_after == audit_before, (audit_before, audit_after)
        log.info("5 次自助查询：用量计数不变(%d)，审计条数不变(%d)",
                 u_after, audit_after)

    def test_pending_amendment_visible(self):
        self.gateway.amendments.request(
            "t1", self.cid, add_scopes=["payments:write"], extend_seconds=600)
        ins = self.gateway.insights.consent_insight("t1", self.cid)
        pend = ins["pending_amendment"]
        assert pend is not None
        assert pend["add_scopes"] == ["payments:write"]
        assert pend["extend_seconds"] == 600
        # 待生效期间同意概要仍是旧作用域
        assert ins["consent"]["scopes"] == ["accounts:read"]

    def test_insight_only_returns_own_consent_events(self):
        # t2 的同意即使存在访问记录，也不会出现在 t1 的视图里
        key2 = self.issue_key("t2", scopes=["accounts:read", "consents:read"])
        cid2 = self.create_authorised_consent("t2", "acct-x", ["accounts:read"])
        self.client.get("/t/t2/accounts/acct-x", params={"consent_id": cid2},
                        headers=key2["headers"])
        ins = self.gateway.insights.consent_insight("t1", self.cid)
        resources = {r.get("resource") for r in ins["recent_access"]}
        assert "acct-x" not in resources


if __name__ == "__main__":
    unittest.main()
