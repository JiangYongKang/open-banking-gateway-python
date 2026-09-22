"""令牌签名校验与密钥轮换：算法白名单、轮换并存、退役/未知/签名错/过期区分。"""
from __future__ import annotations

import base64
import json
import logging
import unittest

from tests.support import GatewayTestCase

log = logging.getLogger("test.tokens")


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()


class TokenRotationTest(GatewayTestCase):
    def setUp(self):
        super().setUp()
        self.register("t1")
        self.register("t2")

    def _token(self, scopes=None, ttl=3600.0, key_id=None):
        body = {"scopes": scopes or ["accounts:read"], "ttl_seconds": ttl}
        if key_id:
            body["key_id"] = key_id
        r = self.client.post("/admin/tenants/t1/tokens", json=body, headers=self.admin)
        assert r.status_code == 200, r.text
        return r.json()

    def _call(self, token, tenant="t1"):
        r = self.client.get(
            f"/t/{tenant}/accounts/acct-1",
            params={"consent_id": "consent-x"},
            headers={"X-Tenant-Id": tenant, "Authorization": f"Bearer {token}"},
        )
        code = r.json()["error"]["code"] if r.status_code != 200 else "ok"
        log.info("令牌判定 tenant=%s token_head=%s => status=%s code=%s",
                 tenant, token.split(".")[0][:18], r.status_code, code)
        return r.status_code, code

    def test_rotation_coexistence_then_retire(self):
        ka = self.client.post("/admin/tenants/t1/signing-keys", headers=self.admin).json()["kid"]
        old = self._token(key_id=ka)["access_token"]
        # 轮换：新旧并存
        kb = self.client.post("/admin/tenants/t1/signing-keys", headers=self.admin).json()["kid"]
        new = self._token()["access_token"]
        assert self._token(key_id=kb)["kid"] == kb
        # 正常请求（同意不存在属于业务错误，证明令牌本身通过了校验）
        assert self._call(old)[1] == "consent_not_found"
        assert self._call(new)[1] == "consent_not_found"
        # 旧密钥全部退役：旧两个密钥的令牌明确 token_key_retired，
        # 新密钥签发的令牌仍正常过签名校验
        self.client.post("/admin/tenants/t1/signing-keys?retire_old=true", headers=self.admin)
        assert self._call(old)[1] == "token_key_retired"
        assert self._call(new)[1] == "token_key_retired"
        newest = self._token()["access_token"]
        assert self._call(newest)[1] == "consent_not_found"

    def test_token_error_matrix(self):
        kid = self.client.post("/admin/tenants/t1/signing-keys", headers=self.admin).json()["kid"]
        tok = self._token()["access_token"]
        # 签名错误
        assert self._call(tok[:-3] + "xxx")[1] == "token_bad_signature"
        # 算法不允许（none）
        h = _b64({"alg": "none", "kid": kid})
        p = _b64({"iss": "t1", "scope": ["accounts:read"]})
        assert self._call(f"{h}.{p}.")[1] == "token_algorithm_not_allowed"
        # 未知 kid
        h = _b64({"alg": "HS256", "kid": "kid-ghost"})
        assert self._call(f"{h}.{p}.aaa")[1] == "token_key_unknown"
        # 过期
        expired = self._token(ttl=-1)["access_token"]
        assert self._call(expired)[1] == "token_expired"
        # 畸形
        assert self._call("a.b")[1] == "token_malformed"
        # 跨租户：t2 的密钥集合里没有 t1 的 kid
        assert self._call(tok, tenant="t2")[1] == "token_key_unknown"

    def test_token_tenant_issuer_mismatch(self):
        self.client.post("/admin/tenants/t1/signing-keys", headers=self.admin)
        tok = self._token()["access_token"]
        # 给 t2 也建密钥；t1 令牌中的 iss=t1，在 t2 入口直接 kid 未知，
        # 不会走到 iss 比对；构造同 kid 不存在场景下仍应安全拒绝
        self.client.post("/admin/tenants/t2/signing-keys", headers=self.admin)
        status, code = self._call(tok, tenant="t2")
        assert code == "token_key_unknown"


if __name__ == "__main__":
    unittest.main()
