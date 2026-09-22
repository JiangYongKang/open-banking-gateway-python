"""并发幂等：多线程同时触发同一事件，只允许一次首次投递。"""
from __future__ import annotations

import logging
import threading
import unittest

from tests.support import GatewayTestCase

log = logging.getLogger("test.concurrent")


class ConcurrentTriggerTest(GatewayTestCase):
    def test_concurrent_same_event_triggered_once(self):
        self.register("t1")
        gw = self.gateway
        delivered = {"count": 0}
        lock = threading.Lock()

        def counting_sender(record):
            with lock:
                delivered["count"] += 1

        gw.callbacks._sender = counting_sender

        errors = []
        barrier = threading.Barrier(16)

        def fire():
            barrier.wait()
            try:
                gw.callbacks.trigger("evt-race", "t1", "t", {"k": "v"})
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=fire) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, errors
        st = gw.callbacks.status("evt-race")
        log.info("16 并发触发同一事件: attempts=%d status=%s sender_calls=%d",
                 st["attempts"], st["status"], delivered["count"])
        assert st["status"] == "delivered"
        assert st["attempts"] == 1
        assert delivered["count"] == 1


if __name__ == "__main__":
    unittest.main()


class ConcurrentConsentTransitionTest(GatewayTestCase):
    def test_concurrent_authorise_single_winner(self):
        self.register("t1")
        gw = self.gateway
        cid = gw.consents.create("t1", "acct-1", ["accounts:read"], 3600)["consent_id"]
        outcomes = {"ok": 0, "rejected": 0}
        lock = threading.Lock()
        barrier = threading.Barrier(12)

        def authorise():
            barrier.wait()
            try:
                gw.consents.authorise("t1", cid)
                with lock:
                    outcomes["ok"] += 1
            except Exception:
                with lock:
                    outcomes["rejected"] += 1

        threads = [threading.Thread(target=authorise) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        rec = gw.consents.get("t1", cid)
        log.info("12 并发授权: ok=%d rejected=%d status=%s version=%d history=%d",
                 outcomes["ok"], outcomes["rejected"], rec["status"], rec["version"],
                 len(rec["history"]))
        assert outcomes["ok"] == 1
        assert outcomes["rejected"] == 11
        assert rec["status"] == "authorised"
        assert rec["version"] == 2
        assert len(rec["history"]) == 2  # create + authorise，无重复流转


class HttpWebhookLoopbackTest(GatewayTestCase):
    """使用 uvicorn 本地起服，webhook http 模式投递到本应用 /callbacks/receive。"""

    def test_http_loopback_delivery(self):
        import threading
        import time
        import httpx

        gw = self.gateway
        gw.registry.register_tenant("t1", "租户一")

        import uvicorn

        config = uvicorn.Config(self.app, host="127.0.0.1", port=8931,
                                log_level="error", lifespan="off")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        try:
            base = "http://127.0.0.1:8931"
            # 等待端口就绪
            for _ in range(50):
                try:
                    if httpx.get(base + "/health", timeout=0.5).status_code == 200:
                        break
                except httpx.TransportError:
                    time.sleep(0.05)

            admin = {"X-Admin-Token": "local-admin"}
            # webhook 回环投递给自己
            cfg = httpx.put(base + "/admin/tenants/t1/webhook",
                            json={"mode": "http", "url": base + "/callbacks/receive"},
                            headers=admin, timeout=2)
            assert cfg.status_code == 200, cfg.text
            key = httpx.post(base + "/admin/tenants/t1/keys",
                             json={"scopes": ["callbacks:write"]},
                             headers=admin, timeout=2).json()
            headers = {"X-Tenant-Id": "t1",
                       "X-API-Key": f"{key['key_id']}:{key['secret']}"}
            r = httpx.post(base + "/t/t1/callbacks/trigger",
                           json={"event_id": "evt-http", "event_type": "ping",
                                 "payload": {"msg": "hello"}},
                           headers=headers, timeout=2)
            assert r.status_code == 200, r.text
            st = httpx.get(base + "/admin/events/evt-http", headers=admin, timeout=2).json()
            log.info("HTTP 回环投递: status=%s attempts=%d", st["status"], st["attempts"])
            assert st["status"] == "delivered" and st["attempts"] == 1
        finally:
            server.should_exit = True
            thread.join(timeout=3)
            gw.close()
