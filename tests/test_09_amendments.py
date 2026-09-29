"""同意变更（amendment）：待生效不打断在跑业务、批准后新作用域/有效期生效、
撤销/到期撞变更按终态算且变更作废、旧版本只增不改可追溯。"""
from __future__ import annotations

import logging

from tests.support import GatewayTestCase

log = logging.getLogger("test.amendments")


class AmendmentLifecycleTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")
        self.key = self.issue_key(
            "t1", scopes=["accounts:read", "payments:write", "consents:write"]
        )
        self.now = 1_000_000.0

    def _authorised_consent(self, ttl=3600.0):
        rec = self.gateway.consents.create(
            "t1", "acct-1", ["accounts:read"], ttl_seconds=ttl
        )
        self.gateway.consents.authorise("t1", rec["consent_id"])
        return rec["consent_id"]

    def test_pending_amendment_keeps_business_running(self):
        gw = self.gateway
        cid = self._authorised_consent()
        out = gw.consents.request_amendment(
            "t1", cid, add_scopes=["payments:write"], extend_ttl_seconds=600
        )
        aid = out["amendment"]["amendment_id"]
        rec = gw.consents.get("t1", cid)
        # 待生效期间：原作用域/有效期不变
        assert rec["scopes"] == ["accounts:read"]
        assert rec["expires_at"] == self.now + 3600
        assert rec["status"] == "authorised"
        # 原业务照常放行
        r = self.client.get(f"/t/t1/accounts/acct-1", params={"consent_id": cid},
                            headers=self.key["headers"])
        assert r.status_code == 200, r.text
        # 新作用域尚未生效 -> 仍按旧作用域拒绝（这里直接断言记录里没有）
        assert "payments:write" not in rec["scopes"]
        # 变更记录处于 pending，带变更前快照
        amd = gw.consents.list_amendments("t1", cid)[0]
        assert amd["status"] == "pending"
        assert amd["before"]["scopes"] == ["accounts:read"]
        assert amd["proposed_scopes"] == ["accounts:read", "payments:write"]
        log.info("待生效变更 %s 不影响在跑授权，访问仍 200", aid)

    def test_approve_applies_new_scopes_and_extended_expiry(self):
        gw = self.gateway
        cid = self._authorised_consent()
        out = gw.consents.request_amendment(
            "t1", cid, add_scopes=["payments:write"], extend_ttl_seconds=600
        )
        aid = out["amendment"]["amendment_id"]
        gw.consents.approve_amendment("t1", cid, aid)
        rec = gw.consents.get("t1", cid)
        assert rec["scopes"] == ["accounts:read", "payments:write"]
        assert rec["expires_at"] == self.now + 3600 + 600
        assert rec["ttl_seconds"] == 4200.0
        amd = gw.consents.list_amendments("t1", cid)[0]
        assert amd["status"] == "approved"
        assert amd["after"]["scopes"] == ["accounts:read", "payments:write"]
        # 原作用域仍在、新作用域也可用
        assert gw.consents.check_access("t1", cid, "acct-1", "accounts:read")
        assert gw.consents.check_access("t1", cid, "acct-1", "payments:write")

    def test_only_extend_ttl_allowed(self):
        gw = self.gateway
        cid = self._authorised_consent()
        out = gw.consents.request_amendment("t1", cid, extend_ttl_seconds=120)
        gw.consents.approve_amendment("t1", cid, out["amendment"]["amendment_id"])
        rec = gw.consents.get("t1", cid)
        assert rec["scopes"] == ["accounts:read"]
        assert rec["expires_at"] == self.now + 3600 + 120

    def test_no_change_request_rejected(self):
        from app.errors import ConsentAmendmentNoChangeError

        cid = self._authorised_consent()
        try:
            self.gateway.consents.request_amendment(
                "t1", cid, add_scopes=[], extend_ttl_seconds=0
            )
            assert False, "必须拒绝空变更"
        except ConsentAmendmentNoChangeError as e:
            assert e.code == "consent_amendment_no_change"

    def test_reject_amendment_leaves_authorisation_intact(self):
        gw = self.gateway
        cid = self._authorised_consent()
        out = gw.consents.request_amendment(
            "t1", cid, add_scopes=["payments:write"], extend_ttl_seconds=600
        )
        aid = out["amendment"]["amendment_id"]
        gw.consents.reject_amendment("t1", cid, aid)
        rec = gw.consents.get("t1", cid)
        assert rec["scopes"] == ["accounts:read"]
        assert rec["expires_at"] == self.now + 3600
        assert gw.consents.list_amendments("t1", cid)[0]["status"] == "rejected"
        # 驳回后可提交新的变更
        out2 = gw.consents.request_amendment("t1", cid, extend_ttl_seconds=30)
        assert out2["amendment"]["status"] == "pending"

    def test_cannot_request_on_revoked_consent(self):
        from app.errors import ConsentAmendmentInvalidStateError

        cid = self._authorised_consent()
        self.gateway.consents.revoke("t1", cid)
        try:
            self.gateway.consents.request_amendment(
                "t1", cid, add_scopes=["payments:write"], extend_ttl_seconds=600
            )
            assert False
        except ConsentAmendmentInvalidStateError as e:
            assert e.code == "consent_amendment_invalid_state"

    def test_only_one_pending_amendment(self):
        from app.errors import ConsentAmendmentPendingError

        cid = self._authorised_consent()
        self.gateway.consents.request_amendment("t1", cid, extend_ttl_seconds=60)
        try:
            self.gateway.consents.request_amendment("t1", cid, extend_ttl_seconds=90)
            assert False
        except ConsentAmendmentPendingError as e:
            assert e.code == "consent_amendment_pending"

    def test_revoke_while_pending_voids_amendment_and_blocks_new_scope(self):
        from app.errors import (
            ConsentAmendmentNotPendingError,
            ConsentRevokedError,
        )

        gw = self.gateway
        cid = self._authorised_consent()
        out = gw.consents.request_amendment(
            "t1", cid, add_scopes=["payments:write"], extend_ttl_seconds=10_000
        )
        aid = out["amendment"]["amendment_id"]
        # 撤销撞待生效变更
        gw.consents.revoke("t1", cid)
        amd = [a for a in gw.consents.get("t1", cid)["amendments"]
               if a["amendment_id"] == aid][0]
        assert amd["status"] == "voided"
        # 事后再点批准：明确失败，绝不生效
        try:
            gw.consents.approve_amendment("t1", cid, aid)
            assert False
        except ConsentAmendmentNotPendingError as e:
            assert e.code == "consent_amendment_not_pending"
        rec = gw.consents.get("t1", cid)
        assert rec["scopes"] == ["accounts:read"]  # 新作用域从未写入
        # version 与 history 长度始终一致（作废也是一个版本事件）
        assert rec["version"] == len(rec["history"])
        # 撤销后任何访问都拒绝
        try:
            gw.consents.check_access("t1", cid, "acct-1", "accounts:read")
            assert False
        except ConsentRevokedError:
            pass
        try:
            gw.consents.check_access("t1", cid, "acct-1", "payments:write")
            assert False
        except ConsentRevokedError:
            pass

    def test_expire_while_pending_voids_amendment(self):
        from app.errors import ConsentAmendmentNotPendingError

        gw = self.gateway
        cid = self._authorised_consent(ttl=100)
        out = gw.consents.request_amendment(
            "t1", cid, add_scopes=["payments:write"], extend_ttl_seconds=10_000
        )
        aid = out["amendment"]["amendment_id"]
        # 时钟推过到期点，扫描器转 EXPIRED
        self.now += 101
        assert gw.consents.expire_due(now=self.now) == [cid]
        amd = [a for a in gw.consents.get("t1", cid)["amendments"]
               if a["amendment_id"] == aid][0]
        assert amd["status"] == "voided"
        try:
            gw.consents.approve_amendment("t1", cid, aid)
            assert False
        except ConsentAmendmentNotPendingError:
            pass
        # 到期后即使没跑扫描器，访问闸门也即时拒绝并作废
        assert gw.consents.get("t1", cid)["scopes"] == ["accounts:read"]

    def test_lazy_expire_in_access_gate_voids_pending_amendment(self):
        gw = self.gateway
        cid = self._authorised_consent(ttl=10)
        out = gw.consents.request_amendment(
            "t1", cid, add_scopes=["payments:write"], extend_ttl_seconds=999
        )
        aid = out["amendment"]["amendment_id"]
        self.now += 11  # 不调用 expire_due，直接打访问闸门
        from app.errors import ConsentExpiredError

        try:
            gw.consents.check_access("t1", cid, "acct-1", "accounts:read")
            assert False
        except ConsentExpiredError:
            pass
        rec = gw.consents.get("t1", cid)
        assert rec["status"] == "expired"
        amd = [a for a in rec["amendments"] if a["amendment_id"] == aid][0]
        assert amd["status"] == "voided"

    def test_history_and_versions_append_only(self):
        gw = self.gateway
        cid = self._authorised_consent()
        out1 = gw.consents.request_amendment("t1", cid, extend_ttl_seconds=60)
        gw.consents.approve_amendment("t1", cid, out1["amendment"]["amendment_id"])
        out2 = gw.consents.request_amendment(
            "t1", cid, add_scopes=["payments:write"], extend_ttl_seconds=30
        )
        gw.consents.reject_amendment("t1", cid, out2["amendment"]["amendment_id"])
        rec = gw.consents.get("t1", cid)
        actions = [h["action"] for h in rec["history"]]
        assert actions == [
            "create", "consent_authorise",
            "consent_amendment_request", "consent_amendment_approve",
            "consent_amendment_request", "consent_amendment_reject",
        ]
        # version 与 history 长度一致，单调递增
        assert rec["version"] == len(rec["history"]) == 6
        # 旧版本快照保留：批准产生的 revision 记录了当时作用域
        assert len(rec["revisions"]) == 2
        assert rec["revisions"][0]["event"] == "consent_amendment_approve"
        # 两条变更记录都在，未被覆盖
        statuses = [a["status"] for a in rec["amendments"]]
        assert statuses == ["approved", "rejected"]
        log.info("变更全程只增不改: history=%s revisions=%d", actions,
                 len(rec["revisions"]))


if __name__ == "__main__":
    import unittest

    unittest.main()
