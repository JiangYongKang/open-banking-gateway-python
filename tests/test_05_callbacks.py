"""回调事件：幂等触发、退避重试、最终死信、并发重复、事件状态隔离。"""
from __future__ import annotations

import threading

from tests.conftest import auth, token


def _trigger(client, hdr, event_id, url):
    return client.post("/partner/callbacks/trigger", headers=hdr,
                       json={"event_id": event_id, "callback_url": url,
                             "payload": {"v": 1}})


def test_success_delivered_first_try(client):
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    r = _trigger(client, auth(tok), "e-ok", "https://example/cb")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "delivered" and body["attempts"] == 1


def test_duplicate_trigger_is_idempotent(client):
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    r1 = _trigger(client, hdr, "e-dup", "https://example/cb")
    r2 = _trigger(client, hdr, "e-dup", "https://example/cb")
    r3 = _trigger(client, hdr, "e-dup", "https://example/cb")
    assert r1.json()["attempts"] == 1
    assert r2.json()["attempts"] == 1
    assert r3.json()["attempts"] == 1
    delivered = [d for d in client.state.caller.delivered if d[0] == "e-dup"]
    assert len(delivered) == 1


def test_backoff_then_recovery_then_delivered(client):
    state = client.state
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    r = _trigger(client, hdr, "e-tr", "http://:transient:/cb")
    body = r.json()
    assert body["status"] == "retrying" and body["attempts"] == 1
    # 退避未到直接要求投递：被拒
    r = client.post("/admin/callbacks/e-tr/deliver")
    # deliver_until_settled 会自动推进时钟，最终成功
    assert r.status_code == 200
    assert r.json()["status"] == "delivered"
    assert r.json()["attempts"] == 3
    # 退避间隔：1s, 2s（base=1, factor=2）
    hist = state.callbacks.get("e-tr").attempt_history
    backoffs = [h.get("backoff") for h in hist if h.get("result") == "retrying"]
    assert backoffs == [1.0, 2.0]


def test_permanent_failure_reaches_dead_state(client):
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    _trigger(client, hdr, "e-dead", "fail://cb")
    r = client.post("/admin/callbacks/e-dead/deliver")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "dead"
    assert body["attempts"] == body["max_attempts"] == 4
    assert body["last_error"]
    # 死信后再触发/再投递均不得重复
    r = _trigger(client, hdr, "e-dead", "fail://cb")
    assert r.json()["status"] == "dead" and r.json()["attempts"] == 4
    # 事件状态可查询
    r = client.get("/partner/callbacks/e-dead", headers=hdr)
    assert r.json()["status"] == "dead"


def test_event_states_do_not_pollute_each_other(client):
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    _trigger(client, hdr, "e-a", "https://ok")          # 成功
    _trigger(client, hdr, "e-b", "fail://cb")           # 失败
    client.post("/admin/callbacks/e-b/deliver")          # b 进死信
    assert client.get("/partner/callbacks/e-a", headers=hdr).json()["status"] == "delivered"
    assert client.get("/partner/callbacks/e-b", headers=hdr).json()["status"] == "dead"


def test_concurrent_duplicate_trigger_single_delivery(client):
    tok = token(client, "cred-tenant-a", "partner-secret-a")
    hdr = auth(tok)
    errors = []
    lock = threading.Lock()

    def fire():
        try:
            _trigger(client, hdr, "e-race", "https://example/cb")
        except BaseException as exc:  # noqa: BLE001
            with lock:
                errors.append(repr(exc))

    threads = [threading.Thread(target=fire) for _ in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors[:3]
    event = client.state.callbacks.get("e-race")
    assert event.attempts == 1
    assert len([d for d in client.state.caller.delivered if d[0] == "e-race"]) == 1


def test_cross_tenant_callback_isolation(client):
    tokA = token(client, "cred-tenant-a", "partner-secret-a")
    tokB = token(client, "cred-tenant-b", "partner-secret-b")
    _trigger(client, auth(tokA), "shared-id", "https://a")
    # B 不能用相同 id 顶替，也不能查询 A 的事件
    r = _trigger(client, auth(tokB), "shared-id", "https://b")
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "tenant_mismatch"
    r = client.get("/partner/callbacks/shared-id", headers=auth(tokB))
    assert r.status_code == 403
