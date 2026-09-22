"""本地存储原子落盘/恢复与关键单元边界。"""
from __future__ import annotations

from app.clock import Clock
from app.config import Settings
from app.models import (Consent, ConsentHistoryEntry, ConsentStatus,
                        KeyState, SigningKey)
from app.services.keys import KeyService
from app.storage import Storage
from app.audit import AuditLog
from app.services.consents import ConsentService


def test_storage_roundtrip_preserves_consent_history(tmp_path):
    s = Storage()
    s.keys["k"] = SigningKey(kid="k", alg="HS256", secret="sec",
                             state=KeyState.ACTIVE, created_at=1.0)
    s.consents["c"] = Consent(
        consent_id="c", tenant_id="t", scopes=["balances"], account_ids=["a"],
        status=ConsentStatus.AUTHORIZED, created_at=1.0, expires_at=9.0,
        history=[ConsentHistoryEntry(at=1.0, action="created",
                                     from_status=None, to_status="pending"),
                 ConsentHistoryEntry(at=2.0, action="authorized",
                                     from_status="pending",
                                     to_status="authorized")])
    path = str(tmp_path / "state.json")
    s.save(path)

    s2 = Storage()
    s2.load(path)
    assert s2.keys["k"].state == KeyState.ACTIVE
    c = s2.consents["c"]
    assert c.status == ConsentStatus.AUTHORIZED
    assert [h.action for h in c.history] == ["created", "authorized"]


def test_retired_key_verify_rejects_even_after_reload(tmp_path):
    s = Storage()
    audit = AuditLog()
    clock = Clock()
    ks = KeyService(s, audit, clock)
    ks.add_key("k1", "HS256", "sec1")
    ks.add_key("k2", "HS256", "sec2")
    ks.retire_key("k1")
    path = str(tmp_path / "state.json")
    s.save(path)

    s2 = Storage()
    s2.load(path)
    ks2 = KeyService(s2, AuditLog(), Clock())
    assert ks2.resolve_for_verify("k2").kid == "k2"
    from app.errors import ErrorCode, GatewayError
    try:
        ks2.resolve_for_verify("k1")
        assert False
    except GatewayError as e:
        assert e.code == ErrorCode.TOKEN_KEY_RETIRED


def test_consent_create_limits_no_residue():
    s, audit, clock = Storage(), AuditLog(), Clock()
    cs = ConsentService(s, audit, Settings(max_scopes=2), clock)
    before = len(s.consents)
    for ttl, scopes in ((0, ["a"]), (["bad"][0] and 5, ["a", "b", "c"])):
        try:
            if isinstance(ttl, int) and ttl == 0:
                cs.create("t", ["a"], [], 0)
            else:
                cs.create("t", ["a", "b", "c"], [], 5)
        except Exception:
            pass
    assert len(s.consents) == before
