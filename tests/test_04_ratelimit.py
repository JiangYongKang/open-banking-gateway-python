"""按租户与按接口的限流/配额：拒绝不耗额度、返回等待秒数、并发不超发。"""
from __future__ import annotations

import threading

import pytest

from app.config import Settings
from app.main import create_app
from app.services.ratelimit import RateLimitService
from app.storage import Storage
from app.clock import Clock
from app.errors import ErrorCode, GatewayError


def _rl(**over):
    s = Storage()
    clk = Clock()
    settings = Settings(rate_limit_default_per_minute=over.get("limit", 5),
                        rate_limit_action=over.get("action", "reject"),
                        delay_timeout_seconds=over.get("delay_timeout", 2.0),
                        daily_quota_default=over.get("quota", 100000))
    rl = RateLimitService(s, settings, clk,
                          sleeper=over.get("sleeper", clk.advance))
    return rl, s, clk


def test_reject_returns_retry_after_and_does_not_consume():
    rl, s, clk = _rl(limit=3)
    for _ in range(3):
        rl.acquire("t1", "ep")
    with pytest.raises(GatewayError) as ei:
        rl.acquire("t1", "ep")
    assert ei.value.code == ErrorCode.RATE_LIMITED_REJECT
    assert ei.value.details["retry_after_seconds"] > 0
    assert ei.value.details["policy"] == "reject"
    # 被拒绝不消耗额度
    assert rl.peek_rate("t1", "ep") == 3


def test_window_rollover_allows_again():
    rl, s, clk = _rl(limit=2)
    rl.acquire("t1", "ep"); rl.acquire("t1", "ep")
    with pytest.raises(GatewayError):
        rl.acquire("t1", "ep")
    clk.advance(61)
    rl.acquire("t1", "ep")  # 新窗口放行
    assert rl.peek_rate("t1", "ep") == 1


def test_tenant_and_endpoint_isolation():
    rl, s, clk = _rl(limit=1)
    rl.acquire("t1", "ep-a")
    # 同租户不同接口独立计数
    rl.acquire("t1", "ep-b")
    # 不同租户独立计数
    rl.acquire("t2", "ep-a")
    with pytest.raises(GatewayError) as ei:
        rl.acquire("t1", "ep-a")
    assert ei.value.code == ErrorCode.RATE_LIMITED_REJECT


def test_concurrent_no_oversell():
    """50 并发抢 10 个额度：成功恰好 10、拒绝恰好 40、计数精确为 10。"""
    rl, s, clk = _rl(limit=10)
    outcomes = []
    lock = threading.Lock()

    def worker():
        try:
            rl.acquire("tc", "ep")
            result = "ok"
        except GatewayError as e:
            result = "reject" if e.code == ErrorCode.RATE_LIMITED_REJECT else "other"
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count("ok") == 10
    assert outcomes.count("reject") == 40
    assert rl.peek_rate("tc", "ep") == 10


def test_delay_policy_times_out_without_consuming():
    rl, s, clk = _rl(limit=1, action="delay", delay_timeout=0.01)
    rl.acquire("t1", "ep")
    with pytest.raises(GatewayError) as ei:
        rl.acquire("t1", "ep")
    assert ei.value.code == ErrorCode.RATE_LIMITED_TIMEOUT
    assert rl.peek_rate("t1", "ep") == 1


def test_delay_policy_succeeds_after_window():
    rl, s, clk = _rl(limit=1, action="delay", delay_timeout=70)
    rl.acquire("t1", "ep")
    rl.acquire("t1", "ep")  # 内部推进时钟到窗口重置
    assert rl.peek_rate("t1", "ep") == 1


def test_daily_quota_rejection_does_not_consume():
    rl, s, clk = _rl(limit=100, quota=2)
    rl.acquire("t1", "ep"); rl.acquire("t1", "ep")
    with pytest.raises(GatewayError) as ei:
        rl.acquire("t1", "ep")
    assert ei.value.code == ErrorCode.QUOTA_EXHAUSTED
    assert rl.peek_quota("t1") == 2


def test_http_429_shape(client):
    """HTTP 层：收紧限额后返回 429 与可解释的等待信息。"""
    from fastapi.testclient import TestClient
    settings = Settings(rate_limit_default_per_minute=1,
                        daily_quota_default=100000)
    app = create_app(settings, seed=True)
    c = TestClient(app)
    r = c.post("/partner/token",
               json={"credential_id": "cred-tenant-a",
                     "secret": "partner-secret-a"})
    tok = r.json()["access_token"]
    hdr = {"Authorization": f"Bearer {tok}"}
    # 第一个请求消耗 token 接口 1 次；再请求同意接口（独立计数，限额 1）
    r1 = c.post("/partner/consents", headers=hdr,
                json={"scopes": ["balances"], "ttl_seconds": 10})
    assert r1.status_code == 200
    r2 = c.post("/partner/consents", headers=hdr,
                json={"scopes": ["balances"], "ttl_seconds": 10})
    assert r2.status_code == 429
    err = r2.json()["error"]
    assert err["code"] == "rate_limited_reject"
    assert err["details"]["retry_after_seconds"] > 0
    assert err["details"]["endpoint"].endswith("/consents")
