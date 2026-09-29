"""测试公共夹具：临时目录网关 + TestClient + 管理辅助。"""
from __future__ import annotations

import logging
import tempfile
import unittest

from fastapi.testclient import TestClient

# 统一测试日志：打印关键输入与判定依据，压低第三方库的访问噪声
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(name)s: %(message)s",
)
for noisy in ("httpx", "httpcore", "urllib3"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

from app.config import Settings
from app.main import create_app
from app.runtime import Gateway


def make_settings(data_dir: str, **overrides) -> Settings:
    base = dict(
        data_dir=data_dir,
        default_rate_limit=100,
        default_rate_window_seconds=60.0,
        default_quota=1000,
        default_quota_window_seconds=86400.0,
        callback_max_attempts=5,
        callback_backoff_base_seconds=0.01,
        callback_backoff_factor=2.0,
        max_payload_bytes=64 * 1024,
    )
    base.update(overrides)
    return Settings(**base)


class GatewayTestCase(unittest.TestCase):
    settings_overrides: dict = {}

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = make_settings(self.tmp.name, **self.settings_overrides)
        self.now = 1_000_000.0
        self.gateway = Gateway(self.settings, clock=lambda: self.now)
        self.app = create_app(self.settings, gateway=self.gateway)
        self.client = TestClient(self.app)
        self.admin = {"X-Admin-Token": "local-admin"}

    def tearDown(self) -> None:
        self.gateway.close()
        self.client.close()
        self.tmp.cleanup()

    # ---- 辅助 ------------------------------------------------------------

    def register(self, tenant_id: str = "t1", name: str = "租户一"):
        r = self.client.post("/admin/tenants", json={"tenant_id": tenant_id, "name": name},
                             headers=self.admin)
        assert r.status_code == 200, r.text
        return tenant_id

    def issue_key(self, tenant_id: str = "t1", scopes=None, ttl=None):
        scopes = scopes or ["accounts:read", "callbacks:write", "usage:read",
                            "consents:write", "consents:read"]
        body: dict = {"scopes": scopes}
        if ttl is not None:
            body["ttl_seconds"] = ttl
        r = self.client.post(f"/admin/tenants/{tenant_id}/keys", json=body, headers=self.admin)
        assert r.status_code == 200, r.text
        data = r.json()
        return {"key_id": data["key_id"], "secret": data["secret"],
                "headers": {"X-Tenant-Id": tenant_id,
                            "X-API-Key": f"{data['key_id']}:{data['secret']}"}}

    def create_authorised_consent(self, tenant_id="t1", resource="acct-1",
                                  scopes=None, ttl=3600.0):
        scopes = scopes or ["accounts:read"]
        r = self.client.post(
            f"/admin/tenants/{tenant_id}/consents",
            json={"resource": resource, "scopes": scopes, "ttl_seconds": ttl},
            headers=self.admin,
        )
        assert r.status_code == 200, r.text
        cid = r.json()["consent_id"]
        r = self.client.post(
            f"/admin/tenants/{tenant_id}/consents/{cid}/authorise", headers=self.admin
        )
        assert r.status_code == 200, r.text
        return cid
