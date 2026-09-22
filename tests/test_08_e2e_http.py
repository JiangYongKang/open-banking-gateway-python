"""端到端 HTTP 串场：从注册到访问、撤销失效、令牌跨入口拒绝、审计可查。"""
from __future__ import annotations

import logging
import unittest

from tests.support import GatewayTestCase

log = logging.getLogger("test.e2e")


class EndToEndHttpTest(GatewayTestCase):
    def test_happy_path_then_revocation_blocks(self):
        # 两个租户
        self.register("acme", "ACME")
        self.register("globex", "Globex")
        key = self.issue_key("acme")

        # 创建同意：未授权时访问被拒
        r = self.client.post(
            "/admin/tenants/acme/consents", headers=self.admin,
            json={"resource": "acct-1", "scopes": ["accounts:read"], "ttl_seconds": 60},
        )
        cid = r.json()["consent_id"]
        r = self.client.get(f"/t/acme/accounts/acct-1", params={"consent_id": cid},
                            headers=key["headers"])
        assert r.status_code == 403 and r.json()["error"]["code"] == "consent_not_authorised"

        # 授权触发回调（local 模式直接成功）
        r = self.client.post(f"/admin/tenants/acme/consents/{cid}/authorise",
                             headers=self.admin)
        assert r.status_code == 200
        evt = self.client.get(f"/admin/events/evt-consent-{cid}", headers=self.admin)
        assert evt.json()["status"] == "delivered"

        # 访问成功
        r = self.client.get(f"/t/acme/accounts/acct-1", params={"consent_id": cid},
                            headers=key["headers"])
        assert r.status_code == 200 and r.json()["balance"] == "1000.00"

        # 撤销之后立刻不可访问
        self.client.post(f"/admin/tenants/acme/consents/{cid}/revoke", headers=self.admin)
        r = self.client.get(f"/t/acme/accounts/acct-1", params={"consent_id": cid},
                            headers=key["headers"])
        assert r.status_code == 403 and r.json()["error"]["code"] == "consent_revoked"

        # 同意详情仍保留完整历史
        rec = self.client.get(f"/admin/tenants/acme/consents/{cid}",
                              headers=self.admin).json()
        states = [h["to"] for h in rec["history"]]
        log.info("端到端同意历史=%s", states)
        assert states == ["pending", "authorised", "revoked"]

    def test_token_cannot_cross_tenant_entry(self):
        self.register("acme")
        self.register("globex")
        self.client.post("/admin/tenants/acme/signing-keys", headers=self.admin)
        tok = self.client.post(
            "/admin/tenants/acme/tokens", headers=self.admin,
            json={"scopes": ["accounts:read"], "ttl_seconds": 3600},
        ).json()["access_token"]
        # acme 的令牌在 globex 入口：kid 在 globex 密钥集合中未知 -> 拒绝
        r = self.client.get(
            "/t/globex/accounts/acct-1", params={"consent_id": "x"},
            headers={"X-Tenant-Id": "globex", "Authorization": f"Bearer {tok}"},
        )
        log.info("跨入口令牌 HTTP=%s code=%s", r.status_code, r.json()["error"]["code"])
        assert r.status_code == 401 and r.json()["error"]["code"] == "token_key_unknown"

    def test_error_body_shape_is_consistent(self):
        r = self.client.get("/t/acme/accounts/acct-1", params={"consent_id": "x"})
        body = r.json()
        assert set(body) == {"error"}
        assert {"code", "message", "tenant_id"} <= set(body["error"])
        assert body["error"]["code"] == "credential_missing"


if __name__ == "__main__":
    unittest.main()
