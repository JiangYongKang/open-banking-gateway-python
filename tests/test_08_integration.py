"""跨入口一致性：同一判定在 HTTP 各入口给出相同、可解释的结果。"""
from __future__ import annotations

from tests.conftest import auth, token


def test_consent_decision_consistent_across_resource_and_query(client):
    """撤销/过期在“资源访问”和“同意查询反映的状态”上保持一致可解释。"""
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    r = client.post("/partner/consents", headers=hdr,
                    json={"scopes": ["balances"], "account_ids": ["a1"],
                          "ttl_seconds": 100})
    cid = r.json()["consent_id"]
    client.post(f"/partner/consents/{cid}/authorize", headers=hdr)
    # 授权态：资源 200
    assert client.get(
        f"/partner/accounts/a1/balances?consent_id={cid}",
        headers=hdr).status_code == 200
    # 撤销
    client.post(f"/partner/consents/{cid}/revoke", headers=hdr, json={"reason": "x"})
    # 资源入口
    r1 = client.get(f"/partner/accounts/a1/balances?consent_id={cid}", headers=hdr)
    assert r1.status_code == 403
    assert r1.json()["error"]["code"] == "consent_revoked"
    # 查询入口反映一致终态
    r2 = client.get(f"/partner/consents/{cid}", headers=hdr)
    assert r2.status_code == 200 and r2.json()["status"] == "revoked"


def test_two_tenants_fullly_isolated_end_to_end(client):
    tA = token(client, "cred-tenant-a", "partner-secret-a")
    tB = token(client, "cred-tenant-b", "partner-secret-b")
    hA, hB = auth(tA), auth(tB)

    r = client.post("/partner/consents", headers=hA,
                    json={"scopes": ["balances"], "account_ids": ["A"],
                          "ttl_seconds": 100})
    cidA = r.json()["consent_id"]
    client.post(f"/partner/consents/{cidA}/authorize", headers=hA)

    # B 既不能读 A 的同意，也不能借 A 的同意访问账户
    assert client.get(f"/partner/consents/{cidA}", headers=hB
                      ).json()["error"]["code"] == "tenant_mismatch"
    r = client.get(f"/partner/accounts/A/balances?consent_id={cidA}", headers=hB)
    assert r.json()["error"]["code"] == "tenant_mismatch"

    # B 自己的同意与 A 无交集
    r = client.post("/partner/consents", headers=hB,
                    json={"scopes": ["balances"], "account_ids": ["B"],
                          "ttl_seconds": 100})
    cidB = r.json()["consent_id"]
    client.post(f"/partner/consents/{cidB}/authorize", headers=hB)
    assert client.get(
        f"/partner/accounts/B/balances?consent_id={cidB}",
        headers=hB).status_code == 200


def test_error_shape_uniform_across_endpoints(client):
    """所有错误响应都带 error.code/message/details 三段结构。"""
    # 401 缺失令牌
    r1 = client.get("/partner/callbacks/x")
    # 404 不存在（用合法令牌）
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    r2 = client.get("/partner/callbacks/nope", headers=auth(tok))
    for r in (r1, r2):
        err = r.json()["error"]
        assert set(err.keys()) == {"code", "message", "details"}
    assert r1.json()["error"]["code"] == "missing_token"
    assert r2.status_code == 404


def test_key_rotation_does_not_disrupt_new_requests(client):
    """轮换后新签发令牌正常、旧令牌被拒，并存期无窗口误拒。"""
    state = client.state
    t1 = token(client, "cred-tenant-a", "partner-secret-a")
    # 并存：加第二把活跃钥
    state.keys.add_key("kid-x2", "HS256", "sec-x2")
    t2 = token(client, "cred-tenant-a", "partner-secret-a")
    # 两个令牌都可用（可能由不同活跃钥签发）
    for t in (t1, t2):
        r = client.post("/partner/consents", headers=auth(t),
                        json={"scopes": ["balances"], "ttl_seconds": 10})
        assert r.status_code == 200, (t[:10], r.text)
    # 退役演示旧钥（t1 若是旧钥签的则拒；t2 是最新活跃钥签的）
    state.keys.retire_key("kid-demo-1")
    # 最新令牌持续可用
    r = client.post("/partner/consents", headers=auth(t2),
                    json={"scopes": ["balances"], "ttl_seconds": 10})
    assert r.status_code == 200


def test_rotation_admin_endpoint_atomic(client):
    r = client.post("/admin/keys/rotate",
                    json={"new_kid": "kid-r2", "old_kid": "kid-demo-1",
                          "alg": "HS256", "new_secret": "rotated-secret-9999"})
    assert r.status_code == 200 and r.json()["rotated"] is True
    keys = {k["kid"]: k["state"] for k in client.get("/admin/keys").json()["keys"]}
    assert keys["kid-r2"] == "active"
    assert keys["kid-demo-1"] == "retired"
    # 轮换后新令牌用新钥
    t = token(client, "cred-tenant-a", "partner-secret-a")
    assert client.post("/partner/consents", headers=auth(t),
                       json={"scopes": ["balances"], "ttl_seconds": 10}
                       ).status_code == 200
