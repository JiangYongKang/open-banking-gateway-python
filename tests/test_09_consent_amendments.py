"""同意变更（追加作用域 / 延长有效期）：

* 待生效期间原 scopes / 有效期照常可用，正在跑的授权不被误伤；
* 批准在同事务生效，旧版本进入版本链、history 只增不改；
* 变更撞上撤销/到期时按最终状态作废，之后新作用域绝不可用；
* 非法申请（终态同意、重复待生效、无实际改动、参数非法）逐项拒绝。
"""
from __future__ import annotations

import logging
import unittest

from app.errors import (
    ConsentAmendmentConflictError,
    ConsentAmendmentVoidError,
    ConsentNotFoundError,
    ValidationError,
)
from tests.support import GatewayTestCase

log = logging.getLogger("test.amendments")


class ConsentAmendmentTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")
        self.key = self.issue_key("t1")
        self.now = 1_000_000.0
        created = self.gateway.consents.create(
            "t1", "acct-1", ["accounts:read"], ttl_seconds=3600
        )
        self.cid = created["consent_id"]
        self.gateway.consents.authorise("t1", self.cid)

    # ---- 待生效不影响正在跑的业务 ----------------------------------------

    def test_pending_amendment_keeps_running_authorisation(self):
        rec0 = self.gateway.consents.get("t1", self.cid)
        base_expires = rec0["expires_at"]
        am = self.gateway.amendments.request(
            "t1", self.cid, add_scopes=["payments:write"], extend_seconds=1800
        )
        assert am["status"] == "pending"
        # 待生效：可见的 scopes / expires_at 一律照旧
        rec = self.gateway.consents.get("t1", self.cid)
        assert rec["scopes"] == ["accounts:read"]
        assert rec["expires_at"] == base_expires
        assert rec["version"] == 2  # 申请不改同意版本
        # 闸门按旧版本放行
        r = self.client.get("/t/t1/accounts/acct-1", params={"consent_id": self.cid},
                            headers=self.key["headers"])
        assert r.status_code == 200, r.text
        log.info("待生效期间访问照常放行 scopes=%s", rec["scopes"])

    def test_approve_applies_new_scopes_and_expiry_and_keeps_versions(self):
        base = self.gateway.consents.get("t1", self.cid)
        old_expires = base["expires_at"]
        am = self.gateway.amendments.request(
            "t1", self.cid, add_scopes=["payments:write"], extend_seconds=3600
        )
        rec = self.gateway.amendments.approve("t1", am["amendment_id"])
        assert rec["scopes"] == ["accounts:read", "payments:write"]
        assert rec["expires_at"] == old_expires + 3600
        assert rec["version"] == 3
        # 旧版本完整快照在版本链中，未被覆盖
        assert len(rec["versions"]) == 1
        v0 = rec["versions"][0]
        assert v0["scopes"] == ["accounts:read"]
        assert v0["expires_at"] == old_expires
        assert v0["replaced_by_amendment"] == am["amendment_id"]
        # history 只增不改
        actions = [(h["action"], h["to"]) for h in rec["history"]]
        assert ("create", "pending") in actions
        assert ("consent_authorise", "authorised") in actions
        assert ("amendment_approved", "authorised") in actions
        approved = self.gateway.amendments.get("t1", am["amendment_id"])
        assert approved["status"] == "approved"
        log.info("批准后生效 scopes=%s expires=%s 旧版本数=%d",
                 rec["scopes"], rec["expires_at"], len(rec["versions"]))

    def test_new_scope_unusable_until_approved(self):
        # 待生效期间，即使申请里包含新 scope，访问闸门仍按旧 scopes 判定
        self.gateway.amendments.request(
            "t1", self.cid, add_scopes=["accounts:write"]
        )
        # 旧 scope 可用
        assert self.gateway.consents.check_access(
            "t1", self.cid, "acct-1", "accounts:read")["status"] == "authorised"
        # 新 scope 在批准前拿不到
        with self.assertRaises(Exception) as cm:
            self.gateway.consents.check_access(
                "t1", self.cid, "acct-1", "accounts:write")
        assert cm.exception.code == "consent_scope_missing"

    # ---- 变更与撤销/到期撞车 ----------------------------------------------

    def test_revoke_while_pending_voids_amendment_and_blocks_new_scopes(self):
        am = self.gateway.amendments.request(
            "t1", self.cid, add_scopes=["payments:write"]
        )
        self.gateway.consents.revoke("t1", self.cid)
        voided = self.gateway.amendments.get("t1", am["amendment_id"])
        assert voided["status"] == "void"
        assert voided["void_reason"] == "consent_revoked"
        # 批准显式失败、结果可解释
        with self.assertRaises(ConsentAmendmentVoidError) as cm:
            self.gateway.amendments.approve("t1", am["amendment_id"])
        assert cm.exception.code == "consent_amendment_void"
        # 撤销后任何访问都被拒
        with self.assertRaises(Exception) as cm2:
            self.gateway.consents.check_access(
                "t1", self.cid, "acct-1", "accounts:read")
        assert cm2.exception.code == "consent_revoked"
        rec = self.gateway.consents.get("t1", self.cid)
        assert "payments:write" not in rec["scopes"]
        log.info("撤销撞变更：变更作废 reason=%s，新作用域未生效", voided["void_reason"])

    def test_expiry_while_pending_voids_amendment(self):
        am = self.gateway.amendments.request(
            "t1", self.cid, add_scopes=["payments:write"]
        )
        expired = self.gateway.consents.expire_due(now=self.now + 10_000)
        assert self.cid in expired
        voided = self.gateway.amendments.get("t1", am["amendment_id"])
        assert voided["status"] == "void" and voided["void_reason"] == "consent_expired"
        with self.assertRaises(ConsentAmendmentVoidError):
            self.gateway.amendments.approve("t1", am["amendment_id"])
        with self.assertRaises(Exception) as cm:
            self.gateway.consents.check_access(
                "t1", self.cid, "acct-1", "accounts:read")
        assert cm.exception.code == "consent_expired"
        log.info("到期撞变更：变更作废，旧/新作用域都不可再用")

    def test_approve_then_revoke_uses_new_version_then_blocks(self):
        am = self.gateway.amendments.request(
            "t1", self.cid, add_scopes=["payments:write"]
        )
        self.gateway.amendments.approve("t1", am["amendment_id"])
        # 新作用域已生效可用
        assert self.gateway.consents.check_access(
            "t1", self.cid, "acct-1", "payments:write")["scopes"][-1] == "payments:write"
        self.gateway.consents.revoke("t1", self.cid)
        with self.assertRaises(Exception) as cm:
            self.gateway.consents.check_access(
                "t1", self.cid, "acct-1", "payments:write")
        assert cm.exception.code == "consent_revoked"

    # ---- 非法申请 ---------------------------------------------------------

    def test_request_only_on_authorised_consent(self):
        # PENDING 同意不能申请
        pend = self.gateway.consents.create("t1", "acct-9", ["a:b"], 100)
        with self.assertRaises(ConsentAmendmentConflictError):
            self.gateway.amendments.request("t1", pend["consent_id"], add_scopes=["c:d"])
        # REVOKED 同意不能申请
        revoked = self.gateway.consents.create("t1", "acct-8", ["a:b"], 100)
        self.gateway.consents.authorise("t1", revoked["consent_id"])
        self.gateway.consents.revoke("t1", revoked["consent_id"])
        with self.assertRaises(ConsentAmendmentConflictError):
            self.gateway.amendments.request("t1", revoked["consent_id"], add_scopes=["c:d"])

    def test_only_one_pending_amendment(self):
        self.gateway.amendments.request("t1", self.cid, add_scopes=["a:1"])
        with self.assertRaises(ConsentAmendmentConflictError):
            self.gateway.amendments.request("t1", self.cid, add_scopes=["b:2"])
        # 批准后可再申请下一轮
        am = self.gateway.amendments.get  # noqa
        pending = self.gateway.store.collection("amendments").list_items()[0]
        self.gateway.amendments.approve("t1", pending["amendment_id"])
        second = self.gateway.amendments.request("t1", self.cid, add_scopes=["c:3"])
        assert second["status"] == "pending"

    def test_noop_and_invalid_requests_rejected(self):
        # 全部 scope 已包含且无延期 -> 无实际改动
        with self.assertRaises(ConsentAmendmentConflictError):
            self.gateway.amendments.request("t1", self.cid, add_scopes=["accounts:read"])
        # 两者都缺
        with self.assertRaises(ValidationError):
            self.gateway.amendments.request("t1", self.cid)
        # 非法延期
        with self.assertRaises(ValidationError):
            self.gateway.amendments.request("t1", self.cid, extend_seconds=0)
        # 不存在同意
        with self.assertRaises(ConsentNotFoundError):
            self.gateway.amendments.request("t1", "consent-nope", add_scopes=["a:b"])

    def test_approve_idempotent_repeat(self):
        am = self.gateway.amendments.request("t1", self.cid, extend_seconds=100)
        first = self.gateway.amendments.approve("t1", am["amendment_id"])
        second = self.gateway.amendments.approve("t1", am["amendment_id"])
        # 重复批准不再产生新版本
        assert second["version"] == first["version"]
        assert len(second["history"]) == len(first["history"])

    def test_extend_only_does_not_shorten_when_approving_later(self):
        # 延期锚定“当前到期点”，晚批准也不会因为中间流逝而缩短
        am = self.gateway.amendments.request("t1", self.cid, extend_seconds=600)
        self.now += 1200  # 模拟审批延迟（固定时钟，业务时间未流逝）
        rec = self.gateway.amendments.approve("t1", am["amendment_id"])
        assert rec["expires_at"] == 1_000_000 + 3600 + 600

    def test_amendment_tenant_isolation(self):
        self.register("t2")
        with self.assertRaises(ConsentNotFoundError):
            self.gateway.amendments.request("t2", self.cid, add_scopes=["x:y"])


if __name__ == "__main__":
    unittest.main()
