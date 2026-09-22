"""审计脱敏与半更新防护、载荷/超时上限、资源清理。"""
from __future__ import annotations

import logging
import unittest

from tests.support import GatewayTestCase, make_settings
from app.runtime import Gateway
from app.main import create_app

log = logging.getLogger("test.audit_limits")


class AuditTest(GatewayTestCase):
    def test_sensitive_fields_masked_and_traceable(self):
        self.register("t1")
        key = self.issue_key("t1")
        # 一次成功 + 一次失败认证
        self.client.get("/t/t1/accounts/acct-1",
                        params={"consent_id": "x"}, headers=key["headers"])
        self.client.get("/t/t1/accounts/acct-1",
                        params={"consent_id": "x"},
                        headers={"X-Tenant-Id": "t1", "X-API-Key": f"{key['key_id']}:bad"})
        entries = self.client.get("/admin/audit", headers=self.admin).json()["entries"]
        for e in entries:
            detail = e["detail"]
            for name in ("secret", "token"):
                if name in detail and isinstance(detail[name], str) and detail[name]:
                    assert detail[name].startswith("*"), (name, detail[name])
                    assert key["secret"] not in detail[name]
        actions = {e["action"] for e in entries}
        log.info("审计动作集合=%s 总条数=%d", actions, len(entries))
        assert "api_key_auth" in actions
        # 明文 secret 绝不出现在任何审计 JSON 文本里
        import json
        raw = json.dumps(entries, ensure_ascii=False)
        assert key["secret"] not in raw

    def test_audit_failure_does_not_silently_half_update(self):
        """审计写入失败时，同意流转事务整体失败，业务状态不变。"""
        self.register("t1")
        gw = self.gateway
        cid = gw.consents.create("t1", "acct-1", ["accounts:read"], 3600)["consent_id"]

        # consents 与 audit 的写入在同一个跨集合事务中；令 audit.json 的暂存
        # 失败，两阶段提交在替换任何正式文件之前中止，consents 也必须保持原状。
        import os
        import app.storage as storage_mod

        orig_stage = storage_mod.Collection._stage_temp

        def stage_fail_audit(self, data):
            if os.path.basename(self._path) == "audit.json":
                raise OSError("audit disk full")
            return orig_stage(self, data)

        storage_mod.Collection._stage_temp = stage_fail_audit
        try:
            with self.assertRaises(OSError):
                gw.consents.authorise("t1", cid)
        finally:
            storage_mod.Collection._stage_temp = orig_stage
        # 业务状态保持 pending，版本不变
        rec = gw.consents.get("t1", cid)
        log.info("审计失败后同意状态=%s version=%d", rec["status"], rec["version"])
        assert rec["status"] == "pending" and rec["version"] == 1

    def test_audit_is_append_only(self):
        self.register("t1")
        key = self.issue_key("t1")
        self.client.get("/t/t1/accounts/acct-1",
                        params={"consent_id": "x"}, headers=key["headers"])
        first = self.client.get("/admin/audit", headers=self.admin).json()["entries"]
        self.client.get("/t/t1/accounts/acct-1",
                        params={"consent_id": "x"}, headers=key["headers"])
        second = self.client.get("/admin/audit", headers=self.admin).json()["entries"]
        assert len(second) >= len(first)
        assert {e["audit_id"] for e in first} <= {e["audit_id"] for e in second}


class PayloadLimitTest(GatewayTestCase):
    settings_overrides = {"max_payload_bytes": 128}

    def test_oversized_payload_rejected_no_partial_state(self):
        self.register("t1")
        key = self.issue_key("t1")
        big = {"event_id": "big", "event_type": "t",
               "payload": {"blob": "x" * 500}}
        r = self.client.post("/t/t1/callbacks/trigger", json=big, headers=key["headers"])
        assert r.status_code == 413 and r.json()["error"]["code"] == "payload_too_large"
        # 未残留任何回调事件
        from app.errors import CallbackNotFoundError
        try:
            self.gateway.callbacks.status("big")
            raise AssertionError("不应有残留事件")
        except CallbackNotFoundError:
            pass


class TimeoutAndCleanupTest(unittest.TestCase):
    def test_upstream_timeout_fails_fast_and_worker_stops_cleanly(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        settings = make_settings(tmp.name)
        gw = Gateway(settings)
        gw.start_retry_worker(interval=0.01)
        gw.start_retry_worker(interval=0.01)  # 重复 start 幂等
        # 模拟慢上游：立即失败，不产生挂起连接
        from app.resources import MockBankService, UpstreamTimeoutError
        bank = MockBankService(delay=10.0, timeout=2.0)
        with self.assertRaises(UpstreamTimeoutError):
            bank.get_account("acct-1")
        # 停止后台线程不泄漏，连接池也可正常关闭
        gw.close()
        assert gw._retry_thread is None
        gw.stop_retry_worker()  # 幂等
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
