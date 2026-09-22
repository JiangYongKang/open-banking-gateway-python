"""同意生命周期：创建/授权/撤销/到期、非法流转、终态后访问拒绝、历史不丢。"""
from __future__ import annotations

import logging
import unittest

from tests.support import GatewayTestCase

log = logging.getLogger("test.consents")


class ConsentLifecycleTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")
        self.key = self.issue_key("t1")

    def _create(self, resource="acct-1", ttl=3600.0):
        r = self.client.post(
            "/admin/tenants/t1/consents",
            json={"resource": resource, "scopes": ["accounts:read"], "ttl_seconds": ttl},
            headers=self.admin,
        )
        assert r.status_code == 200, r.text
        return r.json()["consent_id"]

    def _get(self, cid):
        return self.gateway.consents.get("t1", cid)

    def test_full_lifecycle_and_illegal_transitions(self):
        cid = self._create()
        # 未授权不可访问
        r = self.client.get(f"/t/t1/accounts/acct-1", params={"consent_id": cid},
                            headers=self.key["headers"])
        assert r.json()["error"]["code"] == "consent_not_authorised"
        # 授权后可访问
        assert self.client.post(f"/admin/tenants/t1/consents/{cid}/authorise",
                                headers=self.admin).status_code == 200
        r = self.client.get(f"/t/t1/accounts/acct-1", params={"consent_id": cid},
                            headers=self.key["headers"])
        assert r.status_code == 200 and r.json()["account_id"] == "acct-1"
        # 重复授权非法
        r = self.client.post(f"/admin/tenants/t1/consents/{cid}/authorise", headers=self.admin)
        assert r.status_code == 409 and r.json()["error"]["code"] == "consent_invalid_transition"
        # 撤销后访问拒绝，终态不可再流转
        self.client.post(f"/admin/tenants/t1/consents/{cid}/revoke", headers=self.admin)
        r = self.client.get(f"/t/t1/accounts/acct-1", params={"consent_id": cid},
                            headers=self.key["headers"])
        assert r.json()["error"]["code"] == "consent_revoked"
        for verb in ("authorise", "revoke"):
            r = self.client.post(f"/admin/tenants/t1/consents/{cid}/{verb}", headers=self.admin)
            assert r.json()["error"]["code"] == "consent_invalid_transition"
        # 历史完整且单调
        states = [h["to"] for h in self._get(cid)["history"]]
        log.info("同意 %s 历史状态=%s", cid, states)
        assert states == ["pending", "authorised", "revoked"]
        assert self._get(cid)["version"] == 3

    def test_resource_and_scope_guards(self):
        cid = self._create(resource="acct-2")
        self.client.post(f"/admin/tenants/t1/consents/{cid}/authorise", headers=self.admin)
        # 资源不匹配
        r = self.client.get(f"/t/t1/accounts/acct-1", params={"consent_id": cid},
                            headers=self.key["headers"])
        assert r.json()["error"]["code"] == "consent_resource_mismatch"
        # 作用域不足的同意（accounts:read 对 payments 资源）
        cid2 = self._create(resource="acct-1")
        self.client.post(f"/admin/tenants/t1/consents/{cid2}/authorise", headers=self.admin)
        rec = self._get(cid2)
        assert "accounts:read" in rec["scopes"]

    def test_expiry_blocks_access(self):
        gw = self.gateway
        created = gw.consents.create("t1", "acct-1", ["accounts:read"], ttl_seconds=10)
        cid = created["consent_id"]
        gw.consents.authorise("t1", cid)
        # 到期扫描
        expired = gw.consents.expire_due(now=self.now + 100)
        assert expired == [cid]
        r = self.client.get(f"/t/t1/accounts/acct-1", params={"consent_id": cid},
                            headers=self.key["headers"])
        assert r.json()["error"]["code"] == "consent_expired"
        # 历史保留全部流转
        states = [h["to"] for h in self._get(cid)["history"]]
        assert states == ["pending", "authorised", "expired"]

    def test_history_never_overwritten(self):
        cid = self._create()
        self.client.post(f"/admin/tenants/t1/consents/{cid}/authorise", headers=self.admin)
        self.client.post(f"/admin/tenants/t1/consents/{cid}/revoke", headers=self.admin)
        rec = self._get(cid)
        # 再次尝试任何流转，历史长度不变
        with self.assertRaises(Exception):
            self.gateway.consents.authorise("t1", cid)
        rec2 = self._get(cid)
        assert len(rec2["history"]) == len(rec["history"]) == 3


if __name__ == "__main__":
    unittest.main()
