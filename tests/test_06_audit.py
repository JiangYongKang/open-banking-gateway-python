"""审计：授权/拒绝/状态变更均落地；敏感字段脱敏；审计失败不静默半更新。"""
from __future__ import annotations

from app.audit import AuditLog, AuditWriteError
from app.clock import Clock
from app.config import Settings
from app.services.consents import ConsentService
from app.storage import Storage
from app.models import ConsentStatus
from tests.conftest import auth, token


def test_allows_and_denials_are_audited_with_masking(client):
    # 一次成功签发
    client.post("/partner/token",
                json={"credential_id": "cred-tenant-a",
                      "secret": "partner-secret-a"})
    # 一次失败签发（错误密钥）
    client.post("/partner/token",
                json={"credential_id": "cred-tenant-a", "secret": "wrong"})
    entries = client.state.audit.query("tenant-a")
    actions = {e.action for e in entries}
    assert "token_issue" in actions
    denies = [e for e in entries if e.result == "denied"]
    assert denies, "必须记录拒绝"
    # 任何审计上下文都不得出现明文密钥/令牌
    blob = repr(entries)
    assert "partner-secret-a" not in blob
    assert "wrong" not in blob
    # 脱敏字段保留末尾可辨识位
    masked = [e.masked_context["secret"] for e in entries if "secret" in e.masked_context]
    assert masked and all(m.startswith("*") for m in masked)


def test_state_changes_have_traceable_history(client):
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    r = client.post("/partner/consents", headers=hdr,
                    json={"scopes": ["balances"], "account_ids": [],
                          "ttl_seconds": 100})
    cid = r.json()["consent_id"]
    client.post(f"/partner/consents/{cid}/authorize", headers=hdr)
    client.post(f"/partner/consents/{cid}/revoke", headers=hdr, json={"reason": "r"})
    entries = client.state.audit.query("tenant-a")
    sc = [e for e in entries if e.action.startswith("consent_")]
    assert {e.action for e in sc} >= {"consent_created", "consent_authorized",
                                     "consent_revoked"}
    assert all(e.result == "state_change" for e in sc)


def test_audit_file_is_append_only_and_masked(tmp_path):
    path = str(tmp_path / "audit.log")
    log = AuditLog(path=path)
    log.write("t1", "token_issue", "allowed", "ok",
              {"token": "abcdef123456", "secret": "topsecret-value"})
    log.write("t1", "x", "denied", "bad", {"secret": "another-secret"})
    text = path and open(path, encoding="utf-8").read()
    assert "topsecret-value" not in text
    assert "abcdef123456" not in text
    assert text.count("\n") == 2


def test_audit_failure_rolls_back_business_state():
    """fail-closed 审计写失败时，同意状态流转必须回滚，无静默半更新。"""
    storage = Storage()
    good = AuditLog()  # 内存，用于创建
    clock = Clock()
    cs_good = ConsentService(storage, good, Settings(), clock)
    consent = cs_good.create("t1", ["balances"], [], 100)

    bad = AuditLog(path="/nonexistent-obg-dir/audit.log", fail_open=False)
    cs_bad = ConsentService(storage, bad, Settings(), clock)
    try:
        cs_bad.authorize("t1", consent.consent_id)
        assert False, "审计写失败必须抛出"
    except AuditWriteError:
        pass
    # 业务状态保持 PENDING，未追加历史
    assert storage.consents[consent.consent_id].status == ConsentStatus.PENDING
    assert len(storage.consents[consent.consent_id].history) == 1


def test_audit_query_is_tenant_scoped(client):
    token(client, "cred-tenant-a", "partner-secret-a")
    token(client, "cred-tenant-b", "partner-secret-b")
    a = client.state.audit.query("tenant-a")
    b = client.state.audit.query("tenant-b")
    assert a and b
    assert all(e.tenant_id == "tenant-a" for e in a)
    assert all(e.tenant_id == "tenant-b" for e in b)
