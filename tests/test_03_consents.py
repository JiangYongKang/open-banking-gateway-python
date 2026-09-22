"""同意创建/授权/撤销/到期状态机，非法流转拒绝，历史只追加不丢失。"""
from __future__ import annotations

from tests.conftest import auth, token


def _make_authorized(client, hdr, scopes=("balances",), accounts=("acct-1",),
                     ttl=1000):
    r = client.post("/partner/consents", headers=hdr,
                    json={"scopes": list(scopes), "account_ids": list(accounts),
                          "ttl_seconds": ttl})
    assert r.status_code == 200, r.text
    cid = r.json()["consent_id"]
    r = client.post(f"/partner/consents/{cid}/authorize", headers=hdr)
    assert r.status_code == 200, r.text
    return cid


def test_full_lifecycle_and_history(client):
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    cid = _make_authorized(client, hdr)

    r = client.get(f"/partner/consents/{cid}", headers=hdr)
    body = r.json()
    assert body["status"] == "authorized"
    actions = [h["action"] for h in body["history"]]
    assert actions == ["created", "authorized"]

    r = client.post(f"/partner/consents/{cid}/revoke", headers=hdr,
                    json={"reason": "user_logout"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "revoked"
    assert body["revoke_reason"] == "user_logout"
    actions = [h["action"] for h in body["history"]]
    assert actions == ["created", "authorized", "revoked"]


def test_invalid_transitions_rejected(client):
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    r = client.post("/partner/consents", headers=hdr,
                    json={"scopes": ["balances"], "account_ids": [],
                          "ttl_seconds": 100})
    cid = r.json()["consent_id"]
    client.post(f"/partner/consents/{cid}/authorize", headers=hdr)
    # 已授权不能再次授权
    r = client.post(f"/partner/consents/{cid}/authorize", headers=hdr)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "consent_invalid_transition"
    # 撤销后不能再授权（终态）
    client.post(f"/partner/consents/{cid}/revoke", headers=hdr, json={"reason": "x"})
    r = client.post(f"/partner/consents/{cid}/authorize", headers=hdr)
    assert r.status_code == 409


def test_pending_consent_cannot_access(client):
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    r = client.post("/partner/consents", headers=hdr,
                    json={"scopes": ["balances"], "account_ids": ["a"],
                          "ttl_seconds": 100})
    cid = r.json()["consent_id"]
    r = client.get(f"/partner/accounts/a/balances?consent_id={cid}", headers=hdr)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "consent_invalid_transition"


def test_revoked_consent_blocks_resource(client):
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    cid = _make_authorized(client, hdr)
    assert client.get(
        f"/partner/accounts/acct-1/balances?consent_id={cid}",
        headers=hdr).status_code == 200
    client.post(f"/partner/consents/{cid}/revoke", headers=hdr, json={"reason": "r"})
    r = client.get(f"/partner/accounts/acct-1/balances?consent_id={cid}", headers=hdr)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "consent_revoked"


def test_expired_consent_blocks_resource(client):
    state = client.state
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    cid = _make_authorized(client, hdr, ttl=100)
    state.clock.advance(200)
    # 到期扫描
    r = client.post("/admin/consents/expire-due")
    assert r.status_code == 200 and r.json()["expired"] >= 1
    r = client.get(f"/partner/accounts/acct-1/balances?consent_id={cid}", headers=hdr)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "consent_expired"
    # 历史不丢失
    body = client.get(f"/partner/consents/{cid}", headers=hdr).json()
    assert [h["action"] for h in body["history"]] == ["created", "authorized",
                                                      "expired"]


def test_expired_without_scan_still_blocked(client):
    """防御性：即使扫描未运行，超过 expires_at 也不得放行。"""
    state = client.state
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    cid = _make_authorized(client, hdr, ttl=100)
    state.clock.advance(150)
    r = client.get(f"/partner/accounts/acct-1/balances?consent_id={cid}", headers=hdr)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "consent_expired"


def test_scope_and_account_enforcement(client):
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    # 同意只有 balances、账户 acct-1
    cid = _make_authorized(client, hdr, scopes=("balances",),
                           accounts=("acct-1",))
    # 账户不在授权范围
    r = client.get(f"/partner/accounts/acct-2/balances?consent_id={cid}", headers=hdr)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "consent_resource_forbidden"


def test_history_not_overwritten_on_recreate_id(client):
    """consent_id 由服务端生成；撤销记录必须完整保留，且状态不可被覆盖。"""
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    cid = _make_authorized(client, hdr)
    client.post(f"/partner/consents/{cid}/revoke", headers=hdr, json={"reason": "x"})
    consent = client.state.storage.consents[cid]
    assert len(consent.history) == 3
    # 再次撤销是非法流转，状态与历史保持不变
    r = client.post(f"/partner/consents/{cid}/revoke", headers=hdr, json={"reason": "y"})
    assert r.status_code == 409
    consent = client.state.storage.consents[cid]
    assert len(consent.history) == 3
    assert consent.revoke_reason == "x"
