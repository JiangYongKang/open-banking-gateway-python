"""租户接入与合作方凭证校验：缺失/未知/密钥错误/吊销/过期/作用域不足可区分。"""
from __future__ import annotations

from tests.conftest import auth, token


def test_missing_credential_fields(client, caplog):
    r = client.post("/partner/token", json={"credential_id": "", "secret": "x"})
    # Pydantic 422 与业务缺失校验；这里走业务层空字符串
    assert r.status_code in (401, 422)
    if r.status_code == 401:
        assert r.json()["error"]["code"] == "missing_credentials"
    assert "credential" in caplog.text.lower() or r.status_code == 422


def test_unknown_tenant_is_distinguishable(client):
    r = client.post("/partner/token",
                    json={"credential_id": "nope", "secret": "whatever"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unknown_tenant"


def test_wrong_secret_is_distinguishable(client):
    r = client.post("/partner/token",
                    json={"credential_id": "cred-tenant-a", "secret": "bad"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_credential_secret"


def test_valid_credentials_issue_token(client):
    r = client.post(
        "/partner/token",
        json={"credential_id": "cred-tenant-a", "secret": "partner-secret-a"})
    assert r.status_code == 200
    body = r.json()
    assert body["tenant_id"] == "tenant-a"
    assert "balances" in body["scopes"]
    assert body["token_type"] == "Bearer"


def test_revoked_credential_rejected(client):
    state = client.state
    state.auth.revoke_credential("cred-tenant-b")
    r = client.post("/partner/token",
                    json={"credential_id": "cred-tenant-b",
                          "secret": "partner-secret-b"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "credential_revoked"


def test_expired_credential_rejected(client):
    state = client.state
    state.auth.register_credential("cred-exp", "tenant-exp", "secret-exp",
                                   ["balances"], ttl_seconds=10)
    state.clock.advance(50)
    r = client.post("/partner/token",
                    json={"credential_id": "cred-exp", "secret": "secret-exp"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "credential_expired"


def test_revoked_credential_invalidates_existing_token(client):
    state = client.state
    tok = token(client, "cred-tenant-b", "partner-secret-b")
    state.auth.revoke_credential("cred-tenant-b")
    r = client.get("/admin/audit", headers=auth(tok))  # 任意受保护接口
    # /admin 不需要令牌；改用合作方接口
    r = client.post("/partner/consents", headers=auth(tok),
                    json={"scopes": ["balances"], "account_ids": [],
                          "ttl_seconds": 100})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "credential_revoked"


def test_tenant_isolation_never_degrades(client):
    """A 租户令牌访问 B 租户资源必须被隔离拒绝，且错误码稳定。"""
    tokA = token(client, "cred-tenant-a", "partner-secret-a")
    tokB = token(client, "cred-tenant-b", "partner-secret-b")
    # B 创建并授权一个同意
    r = client.post("/partner/consents", headers=auth(tokB),
                    json={"scopes": ["balances"], "account_ids": [],
                          "ttl_seconds": 100})
    cid_b = r.json()["consent_id"]
    client.post(f"/partner/consents/{cid_b}/authorize", headers=auth(tokB))
    # A 不得读到 B 的同意
    r = client.get(f"/partner/consents/{cid_b}", headers=auth(tokA))
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "tenant_mismatch"
    # 无令牌同样拒绝，不得退化为任意租户
    r = client.get(f"/partner/consents/{cid_b}")
    assert r.status_code == 401
