"""合作方凭证与租户隔离异常链路。

覆盖：缺失/不存在/secret 错误/吊销/过期/作用域不足/跨租户越权，
错误原因必须可区分，且不会退化为其它租户身份。
"""
from __future__ import annotations

import logging
import unittest

from tests.support import GatewayTestCase

log = logging.getLogger("test.tenants")


class TenantAuthTest(GatewayTestCase):
    def test_credential_matrix(self):
        self.register("t1")
        self.register("t2")
        key = self.issue_key("t1", scopes=["accounts:read"])
        url = "/t/t1/accounts/acct-1"

        def call(headers=None, tenant_path=None):
            tenant_path = tenant_path or (headers or {}).get("X-Tenant-Id", "t1")
            r = self.client.get(
                f"/t/{tenant_path}/accounts/acct-1",
                params={"consent_id": "consent-x"},
                headers=headers or {},
            )
            code = r.json()["error"]["code"]
            log.info("凭证判定输入 tenant_path=%s headers=%s => code=%s",
                     tenant_path,
                     {k: (v[:12] + "…" if isinstance(v, str) else v)
                      for k, v in (headers or {}).items()},
                     code)
            return r.status_code, code

        # 完全缺失
        assert call() == (401, "credential_missing")
        # 形态错误
        assert call({"X-Tenant-Id": "t1", "X-API-Key": "no-colon"}) == (
            401, "credential_missing")
        # secret 错误
        bad = dict(key["headers"])
        bad["X-API-Key"] = f"{key['key_id']}:wrong-secret"
        assert call(bad) == (401, "credential_bad_secret")
        # t1 凭证拿到 t2 入口（kid 不属于 t2）-> credential_unknown（绝不退化放行）
        cross = {"X-Tenant-Id": "t2", "X-API-Key": f"{key['key_id']}:{key['secret']}"}
        assert call(cross, tenant_path="t2") == (401, "credential_unknown")
        # 不存在的租户
        ghost = dict(key["headers"])
        ghost["X-Tenant-Id"] = "ghost"
        assert call(ghost) == (401, "credential_unknown")
        # 作用域不足
        key_ro = self.issue_key("t1", scopes=["accounts:read"])
        r = self.client.post(
            "/t/t1/callbacks/trigger",
            json={"event_id": "e", "event_type": "t", "payload": {}},
            headers=key_ro["headers"],
        )
        assert r.status_code == 403 and r.json()["error"]["code"] == "scope_insufficient"
        # 吊销
        r = self.client.delete(f"/admin/tenants/t1/keys/{key['key_id']}", headers=self.admin)
        assert r.status_code == 200
        assert call(key["headers"]) == (401, "credential_revoked")
        # 过期
        exp = self.issue_key("t1", ttl=-1)
        assert call(exp["headers"]) == (401, "credential_expired")

        # 每种拒绝都在审计中可追溯，且原因不同
        reasons = {
            e["detail"].get("reason")
            for e in self.client.get("/admin/audit", headers=self.admin).json()["entries"]
            if e["action"] == "api_key_auth" and e["result"] == "denied"
        }
        log.info("审计中的拒绝原因集合=%s", reasons)
        expected = {
            "credential_missing", "credential_bad_secret", "credential_unknown",
            "credential_revoked", "credential_expired", "scope_insufficient",
        }
        assert expected <= reasons, (expected, reasons)

    def test_tenant_data_isolation(self):
        """A 租户不能访问/操作 B 租户的同意记录（管理面直接验证服务层隔离）。"""
        self.register("t1")
        self.register("t2")
        gw = self.gateway
        c1 = gw.consents.create("t1", "acct-1", ["accounts:read"], 3600)
        with self.assertRaises(Exception) as cm:
            gw.consents.get("t2", c1["consent_id"])
        assert cm.exception.code == "consent_not_found"
        with self.assertRaises(Exception) as cm:
            gw.consents.authorise("t2", c1["consent_id"])
        assert cm.exception.code == "consent_not_found"


if __name__ == "__main__":
    unittest.main()
