"""冒烟：应用可创建、健康检查可用、OpenAPI 已生成。"""
from __future__ import annotations

import tempfile
import unittest

from fastapi.testclient import TestClient

from tests.support import GatewayTestCase, make_settings
from app.runtime import Gateway
from app.main import create_app


class SmokeTest(unittest.TestCase):
    def test_health_and_openapi(self):
        with tempfile.TemporaryDirectory() as d:
            gw = Gateway(make_settings(d))
            app = create_app(make_settings(d), gateway=gw)
            client = TestClient(app)
            assert client.get("/health").json() == {"status": "ok"}
            paths = client.get("/openapi.json").json()["paths"]
            assert "/t/{tenant_id}/accounts/{account_id}" in paths
            client.close()
            gw.close()


if __name__ == "__main__":
    unittest.main()
