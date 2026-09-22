"""限流配额与并发：竞争不超发、被拒不耗额度、回滚归还、租户/接口隔离、等待信息。"""
from __future__ import annotations

import logging
import threading
import unittest

from app.ratelimit import LimitConfig
from tests.support import GatewayTestCase, make_settings

log = logging.getLogger("test.ratelimit")


class StrictLimitCase(GatewayTestCase):
    settings_overrides = {
        "default_rate_limit": 5,
        "default_rate_window_seconds": 60.0,
        "default_quota": 100,
        "default_quota_window_seconds": 86400.0,
    }

    def test_rejected_requests_do_not_consume(self):
        self.register("t1")
        key = self.issue_key("t1")
        cid = self.create_authorised_consent()
        ok = 0
        codes = []
        for i in range(8):
            r = self.client.get("/t/t1/accounts/acct-1", params={"consent_id": cid},
                                headers=key["headers"])
            codes.append(r.status_code)
            if r.status_code == 200:
                ok += 1
            else:
                err = r.json()["error"]
                assert err["code"] == "rate_limited"
                assert err["details"]["retry_after"] > 0
                assert err["details"]["limit_kind"] == "rate"
        log.info("8 次请求结果=%s 成功=%d", codes, ok)
        assert ok == 5
        assert codes.count(429) == 3
        # 被拒 3 次不消耗额度：用量恰好为 5
        r = self.client.get("/t/t1/usage", params={"endpoint": "GET /accounts/{id}"},
                            headers=key["headers"])
        assert r.status_code == 200, r.text
        assert r.json()["rate"] == 5, r.json()

    def test_business_rejection_rolls_back_quota(self):
        self.register("t1")
        key = self.issue_key("t1")
        cid = self._unauthorised_consent()
        # 未授权访问 -> 业务拒绝，限流占位应回滚
        for _ in range(3):
            r = self.client.get("/t/t1/accounts/acct-1", params={"consent_id": cid},
                                headers=key["headers"])
            assert r.json()["error"]["code"] == "consent_not_authorised"
        r = self.client.get("/t/t1/usage", params={"endpoint": "GET /accounts/{id}"},
                            headers=key["headers"])
        assert r.json()["rate"] == 0, r.json()

    def _unauthorised_consent(self):
        r = self.client.post(
            "/admin/tenants/t1/consents",
            json={"resource": "acct-1", "scopes": ["accounts:read"], "ttl_seconds": 3600},
            headers=self.admin,
        )
        return r.json()["consent_id"]

    def test_concurrent_no_oversell(self):
        limiter = self.gateway.limiter
        limits = LimitConfig(rate_limit=20, rate_window=60.0,
                             quota=10_000, quota_window=3600.0)
        granted = []
        rejected = []
        lock = threading.Lock()

        def worker():
            try:
                res = limiter.acquire("tc", "endpoint-x", limits)
                with lock:
                    granted.append(res)
            except Exception as e:
                with lock:
                    rejected.append(e.code)

        threads = [threading.Thread(target=worker) for _ in range(80)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        log.info("80 并发抢 20 名额: granted=%d rejected=%d", len(granted), len(rejected))
        assert len(granted) == 20
        assert len(rejected) == 60
        assert all(c == "rate_limited" for c in rejected)
        assert limiter.usage("tc", "endpoint-x", limits)["rate"] == 20

    def test_tenant_and_endpoint_isolation(self):
        limiter = self.gateway.limiter
        limits = LimitConfig(2, 60.0, 100, 3600.0)
        limiter.acquire("a", "e1", limits)
        limiter.acquire("a", "e1", limits)
        # 同租户不同接口不受影响
        limiter.acquire("a", "e2", limits)
        # 不同租户同接口不受影响
        limiter.acquire("b", "e1", limits)
        from app.errors import RateLimitError
        for _ in range(2):
            try:
                limiter.acquire("a", "e1", limits)
                raise AssertionError("应当限流")
            except RateLimitError as e:
                assert e.limit_kind == "rate"


if __name__ == "__main__":
    unittest.main()
