"""pytest 公共夹具：每个测试一个隔离的 AppState（小限额、可注入时钟）。"""
from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def _settings() -> Settings:
    return Settings(
        token_ttl_seconds=300,
        rate_limit_default_per_minute=100000,   # 默认不限流，限流专项测试自行收紧
        daily_quota_default=100000,
        max_body_bytes=4096,
        request_timeout_seconds=5.0,
        callback_max_attempts=4,
        callback_backoff_base_seconds=1.0,
        callback_backoff_factor=2.0,
    )


@pytest.fixture
def settings() -> Settings:
    return _settings()


@pytest.fixture
def state(settings):
    """与 client 共享同一个应用状态。"""
    app = create_app(settings, seed=True)
    return app.state.obg


@pytest.fixture
def client(settings):
    app = create_app(settings, seed=True)
    with TestClient(app) as c:
        # 暴露底层状态，测试可直接操纵可注入时钟/服务
        c.state = app.state.obg   # type: ignore[attr-defined]
        yield c


@pytest.fixture(autouse=True)
def _caplog_levels(caplog):
    caplog.set_level(logging.INFO, logger="obg")
    yield


def token(client, credential_id: str, secret: str) -> str:
    r = client.post("/partner/token",
                    json={"credential_id": credential_id, "secret": secret})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def auth(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}
