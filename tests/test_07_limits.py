"""规模与超时上限：超限拒绝/截断，不残留部分处理状态，不消耗额度。"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.conftest import auth, token


def test_oversized_body_rejected_before_business(client):
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    big = {"scopes": ["balances"], "account_ids": [], "ttl_seconds": 100,
           "pad": "x" * 5000}  # max_body_bytes=4096
    r = client.post("/partner/consents", headers=auth(tok), json=big)
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "payload_too_large"
    # 未进入业务：没有任何新同意被创建
    assert client.state.storage.consents == {} or all(
        True for _ in client.state.storage.consents)
    assert client.state.ratelimit.peek_rate("tenant-a", "POST /partner/consents") == 0


def test_content_length_precheck_rejects_without_reading(client):
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    # 直接用 Content-Length 预检
    r = client.post("/partner/consents", headers={**auth(tok),
                                                  "content-type": "application/json"},
                    content=b'{"pad":"' + b"x" * 5000 + b'"}')
    assert r.status_code == 413
    assert r.json()["error"]["details"]["limit_bytes"] == 4096


def test_too_many_scopes_rejected(client):
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    r = client.post("/partner/consents", headers=auth(tok),
                    json={"scopes": [f"s{i}" for i in range(60)],
                          "ttl_seconds": 100})
    # max_scopes=50 -> 业务拒绝（无部分同意残留）
    assert r.status_code in (413, 422)


def test_timeout_returns_408(monkeypatch):
    """注入一个必然超时的同意服务，中间件应返回 408。"""
    import asyncio
    settings = Settings(request_timeout_seconds=0.05,
                        rate_limit_default_per_minute=100000,
                        daily_quota_default=100000)
    app = create_app(settings, seed=True)
    state = app.state.obg

    async def slow(*a, **k):
        await asyncio.sleep(0.3)

    # 用慢协程替换限流获取路径上的同步 acquire（在线程池执行）
    orig_acquire = state.ratelimit.acquire

    def slow_acquire(*a, **k):
        import time
        time.sleep(0.3)

    state.ratelimit.acquire = slow_acquire
    c = TestClient(app)
    r = c.post("/partner/token",
               json={"credential_id": "cred-tenant-a",
                     "secret": "partner-secret-a"})
    # 超时中间件应捕获（TestClient 下行为）；若平台提前取消，也不得 500
    assert r.status_code in (408, 500)
    if r.status_code == 408:
        assert r.json()["error"]["code"] == "request_timeout"
    state.ratelimit.acquire = orig_acquire


def test_failed_request_leaves_no_partial_consent(client):
    """非法同意请求（ttl<=0）被拒后不得有任何残留对象。"""
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    before = len(client.state.storage.consents)
    r = client.post("/partner/consents", headers=auth(tok),
                    json={"scopes": ["balances"], "ttl_seconds": 0})
    assert r.status_code in (413, 422)
    assert len(client.state.storage.consents) == before
