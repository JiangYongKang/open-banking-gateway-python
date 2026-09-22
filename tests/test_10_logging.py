"""验证关键输入与判定依据出现在单测日志中（便于人工追溯）。"""
from __future__ import annotations

import re

from tests.conftest import auth, token


def test_denial_logs_input_and_decision_basis(client, caplog):
    with caplog.at_level("WARNING", logger="obg.auth"):
        client.post("/partner/token",
                    json={"credential_id": "cred-tenant-a", "secret": "wrong-secret"})
    text = caplog.text
    # 判定动作、错误码与关键输入（凭证标识）必须出现在日志
    assert "partner_auth" in text
    assert "invalid_credential_secret" in text
    assert "cred-tenant-a" in text
    # 密钥属于敏感输入，日志中不得明文出现，应为 <redacted>
    assert "wrong-secret" not in text
    assert "<redacted>" in text


def test_ratelimit_logs_denial_with_numbers(client, caplog):
    from app.clock import Clock
    from app.config import Settings
    from app.main import create_app
    from fastapi.testclient import TestClient
    app = create_app(Settings(rate_limit_default_per_minute=1,
                              daily_quota_default=100000), seed=True)
    c = TestClient(app)
    tok = token(c, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    c.post("/partner/consents", headers=hdr,
           json={"scopes": ["balances"], "ttl_seconds": 10})
    import logging
    with caplog.at_level(logging.WARNING, logger="obg.ratelimit"):
        r = c.post("/partner/consents", headers=hdr,
                   json={"scopes": ["balances"], "ttl_seconds": 10})
    assert r.status_code == 429
    assert "rate_limited_reject" in caplog.text
    assert re.search(r"used=\d+ limit=\d+", caplog.text)
    assert "retry_after" in caplog.text


def test_consent_transition_logs_from_and_to(client, caplog):
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    with caplog.at_level("INFO", logger="obg.consents"):
        r = client.post("/partner/consents", headers=hdr,
                        json={"scopes": ["balances"], "ttl_seconds": 10})
        cid = r.json()["consent_id"]
        client.post(f"/partner/consents/{cid}/authorize", headers=hdr)
    assert "consent authorized" in caplog.text
    assert cid in caplog.text
