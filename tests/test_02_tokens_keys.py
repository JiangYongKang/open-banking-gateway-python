"""访问令牌签名校验、算法白名单与新旧密钥并存轮换。"""
from __future__ import annotations

import json

from app.crypto import b64url_encode, sign
from tests.conftest import auth, token


def _craft_token(state, *, alg, kid, secret, tenant="tenant-a",
                 credential="cred-tenant-a", scopes=None, exp_offset=100.0,
                 tamper_sig=False):
    scopes = scopes or ["balances", "consent:manage"]
    clock = state.clock
    payload = {"jti": "j", "tenant_id": tenant, "credential_id": credential,
               "scopes": scopes, "kid": kid, "alg": alg,
               "iat": clock.now(), "exp": clock.now() + exp_offset}
    head = b64url_encode(json.dumps({"alg": alg, "kid": kid, "typ": "OBG1"},
                                    separators=(",", ":")).encode())
    body = b64url_encode(json.dumps(payload, separators=(",", ":"),
                                    sort_keys=True).encode())
    sig_input = f"{head}.{body}".encode()
    sig_bytes = sign(secret, sig_input, "HS256") if alg in ("HS256",) else b"bad"
    sig = b64url_encode(sig_bytes)
    raw = f"{head}.{body}.{sig}"
    if tamper_sig:
        raw = raw[:-2] + ("aa" if not raw.endswith("aa") else "bb")
    return raw


def test_missing_token(client):
    r = client.post("/partner/consents",
                    json={"scopes": ["balances"], "ttl_seconds": 10})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "missing_token"


def test_malformed_token(client):
    r = client.post("/partner/consents",
                    headers={"Authorization": "Bearer not-a-jwt"},
                    json={"scopes": ["balances"], "ttl_seconds": 10})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "malformed_token"


def test_alg_not_in_whitelist(client):
    raw = _craft_token(client.state, alg="none", kid="kid-demo-1",
                       secret="demo-signing-secret-0001")
    r = client.post("/partner/consents", headers=auth(raw),
                    json={"scopes": ["balances"], "ttl_seconds": 10})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "token_alg_not_allowed"


def test_bad_signature_distinguishable(client):
    raw = _craft_token(client.state, alg="HS256", kid="kid-demo-1",
                       secret="demo-signing-secret-0001", tamper_sig=True)
    r = client.post("/partner/consents", headers=auth(raw),
                    json={"scopes": ["balances"], "ttl_seconds": 10})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "token_bad_signature"


def test_unknown_kid_distinguishable(client):
    raw = _craft_token(client.state, alg="HS256", kid="ghost",
                       secret="whatever")
    r = client.post("/partner/consents", headers=auth(raw),
                    json={"scopes": ["balances"], "ttl_seconds": 10})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "token_key_unknown"


def test_expired_token(client):
    raw = _craft_token(client.state, alg="HS256", kid="kid-demo-1",
                       secret="demo-signing-secret-0001", exp_offset=-1)
    r = client.post("/partner/consents", headers=auth(raw),
                    json={"scopes": ["balances"], "ttl_seconds": 10})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "token_expired"


def test_key_rotation_overlap_and_retirement(client):
    """并存期：加新钥不影响旧令牌；旧钥退役后旧令牌被明确拒绝；
    新钥签发的令牌继续可用。"""
    state = client.state
    old_tok = token(client, "cred-tenant-a", "partner-secret-a")

    # 新增新钥（并存），旧令牌仍可正常使用
    state.keys.add_key("kid-demo-2", "HS256", "demo-signing-secret-0002")
    r = client.post("/partner/consents", headers=auth(old_tok),
                    json={"scopes": ["balances"], "ttl_seconds": 10})
    assert r.status_code == 200

    # 退役旧钥
    state.keys.retire_key("kid-demo-1")
    r = client.post("/partner/consents", headers=auth(old_tok),
                    json={"scopes": ["balances"], "ttl_seconds": 10})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "token_key_retired"

    # 新令牌用新钥签发，正常
    new_tok = token(client, "cred-tenant-a", "partner-secret-a")
    r = client.post("/partner/consents", headers=auth(new_tok),
                    json={"scopes": ["balances"], "ttl_seconds": 10})
    assert r.status_code == 200


def test_three_failure_codes_are_distinct(client):
    """算法不允许 / 签名错误 / 密钥退役三类错误必须互不相同。"""
    state = client.state
    state.keys.add_key("kid-k", "HS256", "secret-k")
    codes = set()

    def code_for(raw):
        r = client.post("/partner/consents", headers=auth(raw),
                        json={"scopes": ["balances"], "ttl_seconds": 10})
        assert r.status_code == 401, r.text
        return r.json()["error"]["code"]

    # 算法不允许（密钥退役前即可判定）
    codes.add(code_for(_craft_token(state, alg="none", kid="kid-k",
                                    secret="secret-k")))
    # 签名错误必须在密钥仍活跃时验证，避免被 retired 抢先判定
    codes.add(code_for(_craft_token(state, alg="HS256", kid="kid-k",
                                    secret="secret-k", tamper_sig=True)))
    # 退役后再验签 -> 密钥已退役
    state.keys.retire_key("kid-k")
    codes.add(code_for(_craft_token(state, alg="HS256", kid="kid-k",
                                    secret="secret-k")))
    assert codes == {"token_alg_not_allowed", "token_bad_signature",
                     "token_key_retired"}


def test_scope_insufficient(client):
    # tenant-b 只有 balances + consent:manage，无 payment
    tok = token(client, "cred-tenant-b", "partner-secret-b")
    # balances 资源接口需要 balances（有），构造需要更高权限：直接造 payment 令牌
    raw = _craft_token(client.state, alg="HS256", kid="kid-demo-1",
                       secret="demo-signing-secret-0001",
                       tenant="tenant-b", credential="cred-tenant-b",
                       scopes=["balances"])
    # 同意管理需要 consent:manage，缺少即拒
    r = client.post("/partner/consents", headers=auth(raw),
                    json={"scopes": ["balances"], "ttl_seconds": 10})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "scope_insufficient"
