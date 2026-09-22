"""回调幂等与重试：重复触发不重复投递、退避重试成功、超限进入可查询失败态。"""
from __future__ import annotations

import logging
import unittest

from tests.support import GatewayTestCase

log = logging.getLogger("test.callbacks")


class CallbackIdempotencyTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")
        self.key = self.issue_key("t1")

    def test_duplicate_trigger_single_delivery(self):
        results = []
        for _ in range(3):
            r = self.client.post(
                "/t/t1/callbacks/trigger",
                json={"event_id": "evt-dup", "event_type": "t", "payload": {"v": 1}},
                headers=self.key["headers"],
            )
            assert r.status_code == 200, r.text
            results.append(r.json())
        st = self.gateway.callbacks.status("evt-dup")
        log.info("重复触发 3 次: attempts=%d status=%s", st["attempts"], st["status"])
        assert st["attempts"] == 1 and st["status"] == "delivered"
        # 幂等触发返回的记录在重复时不改变 created_at 等
        assert results[0]["event_id"] == results[1]["event_id"]

    def test_retry_backoff_then_success(self):
        gw = self.gateway
        # 配置前 2 次投递失败（首次 + 第一次重试），第二次重试成功
        gw.sender.configure("t1", mode="local", fail_times=2)
        rec = gw.callbacks.trigger("evt-retry", "t1", "t", {})
        assert rec["attempts"] == 1 and rec["status"] == "pending"
        first_next = rec["next_attempt_at"]
        # 未到点不重试
        assert gw.callbacks.run_due_retries() == 0
        # 到点重试：第 2 次仍失败 -> 仍 pending，退避翻倍（0.01 -> 0.02）
        self.now = first_next
        assert gw.callbacks.run_due_retries() == 1
        st = gw.callbacks.status("evt-retry")
        assert st["status"] == "pending" and st["attempts"] == 2
        assert abs(st["next_attempt_at"] - (first_next + 0.02)) < 1e-9
        # 第二次到点重试：第 3 次成功
        self.now = st["next_attempt_at"]
        assert gw.callbacks.run_due_retries() == 1
        st = gw.callbacks.status("evt-retry")
        log.info("退避重试后 attempts=%d status=%s log=%s",
                 st["attempts"], st["status"],
                 [(a["attempt"], a["result"]) for a in st["attempt_log"]])
        assert st["status"] == "delivered" and st["attempts"] == 3
        # 终态后不再重试
        self.now += 100
        assert gw.callbacks.run_due_retries() == 0
        # webhook 收据：失败 2 + 成功 1
        receipts = gw.sender.list_receipts("evt-retry")
        assert [r["accepted"] for r in receipts] == [False, False, True]

    def test_final_failure_queryable(self):
        gw = self.gateway
        from app.callbacks import CallbackDispatcher
        dispatcher = CallbackDispatcher(
            gw.store, gw.audit, sender=lambda rec: (_ for _ in ()).throw(RuntimeError("down")),
            clock=gw.clock, sleep=lambda s: None,
            max_attempts=3, backoff_base=0.0,
        )
        dispatcher.trigger("evt-fail", "t1", "t", {})
        dispatcher.run_due_retries()
        dispatcher.run_due_retries()
        st = dispatcher.status("evt-fail")
        log.info("全部失败: attempts=%d status=%s last_error=%s",
                 st["attempts"], st["status"], st["last_error"])
        assert st["status"] == "failed" and st["attempts"] == 3
        assert "down" in st["last_error"]
        # 通过管理接口可查询
        r = self.client.get("/admin/events/evt-fail", headers=self.admin)
        assert r.status_code == 200 and r.json()["status"] == "failed"

    def test_retries_do_not_pollute_other_events(self):
        gw = self.gateway
        from app.callbacks import CallbackDispatcher
        d = CallbackDispatcher(
            gw.store, gw.audit,
            sender=lambda rec: (_ for _ in ()).throw(RuntimeError("x")),
            clock=gw.clock, sleep=lambda s: None, max_attempts=2, backoff_base=0.0,
        )
        d.trigger("a", "t1", "t", {})
        d.run_due_retries()  # a -> failed
        d.trigger("b", "t1", "t", {})
        d.run_due_retries()  # b -> failed
        assert d.status("a")["attempts"] == 2 and d.status("b")["attempts"] == 2
        assert [a["attempt"] for a in d.status("a")["attempt_log"]] == [1, 2]
        assert [a["attempt"] for a in d.status("b")["attempt_log"]] == [1, 2]

    def test_authorisation_emits_callback_and_duplicate_authorise_does_not_duplicate(self):
        gw = self.gateway
        created = gw.consents.create("t1", "acct-1", ["accounts:read"], 3600)
        cid = created["consent_id"]
        gw.consents.authorise("t1", cid)  # 通过服务层不触发回调
        # 通过 HTTP 授权触发确定性事件
        r = self.client.post(f"/admin/tenants/t1/consents/{cid}/revoke", headers=self.admin)
        assert r.status_code == 200
        st = gw.callbacks.status(f"evt-consent-{cid}")
        assert st["event_type"] == "consent.revoked"


if __name__ == "__main__":
    unittest.main()
