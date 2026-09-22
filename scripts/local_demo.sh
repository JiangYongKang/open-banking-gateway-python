#!/usr/bin/env bash
# 端到端本地演示：启动服务 -> 令牌 -> 同意 -> 资源 -> 撤销 -> 回调 -> 轮换 -> 审计
# 不依赖任何外部服务；仅需 curl 与本仓库依赖。
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8000}"

echo "== 启动本地服务（后台） =="
uv run uvicorn main:app --host 127.0.0.1 --port 8000 >/tmp/obg_demo.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null || true' EXIT
sleep 2

j() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d$1)"; }

echo "== 1) 健康检查 =="
curl -s "$BASE/admin/health" | python3 -m json.tool

echo "== 2) A 租户换取令牌（错误密钥应 401 invalid_credential_secret） =="
curl -s -o /dev/null -w "wrong secret -> %{http_code}\n" -X POST "$BASE/partner/token" \
  -H 'content-type: application/json' \
  -d '{"credential_id":"cred-tenant-a","secret":"WRONG"}'
TOK=$(curl -s -X POST "$BASE/partner/token" -H 'content-type: application/json' \
  -d '{"credential_id":"cred-tenant-a","secret":"partner-secret-a"}' | j "['access_token']")
echo "A token: ${TOK:0:24}..."

echo "== 3) 创建并授权同意 =="
CID=$(curl -s -X POST "$BASE/partner/consents" -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' \
  -d '{"scopes":["balances"],"account_ids":["acct-1"],"ttl_seconds":600}' | j "['consent_id']")
echo "consent: $CID"
curl -s -X POST "$BASE/partner/consents/$CID/authorize" -H "authorization: Bearer $TOK" \
  -o /dev/null -w "authorize -> %{http_code}\n"

echo "== 4) 访问资源（200）与撤销后访问（403 consent_revoked） =="
curl -s "$BASE/partner/accounts/acct-1/balances?consent_id=$CID" \
  -H "authorization: Bearer $TOK" -o /dev/null -w "balances -> %{http_code}\n"
curl -s -X POST "$BASE/partner/consents/$CID/revoke" -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' -d '{"reason":"demo"}' -o /dev/null \
  -w "revoke -> %{http_code}\n"
curl -s "$BASE/partner/accounts/acct-1/balances?consent_id=$CID" \
  -H "authorization: Bearer $TOK" -o /dev/null -w "balances after revoke -> %{http_code}\n"

echo "== 5) 回调：幂等成功 / 永久失败进入死信 =="
curl -s -X POST "$BASE/partner/callbacks/trigger" -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' \
  -d '{"event_id":"demo-ok","callback_url":"https://example/cb","payload":{}}' \
  -o /dev/null -w "trigger #1 -> %{http_code}\n"
curl -s -X POST "$BASE/partner/callbacks/trigger" -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' \
  -d '{"event_id":"demo-ok","callback_url":"https://example/cb","payload":{}}' \
  | python3 -c "import sys,json;print('dup trigger attempts =',json.load(sys.stdin)['attempts'])"
curl -s -X POST "$BASE/partner/callbacks/trigger" -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' \
  -d '{"event_id":"demo-fail","callback_url":"fail://cb","payload":{}}' -o /dev/null
curl -s -X POST "$BASE/admin/callbacks/demo-fail/deliver" \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print('fail event ->',d['status'],'attempts =',d['attempts'])"

echo "== 6) 密钥轮换：新钥并存、退役旧钥、旧令牌被拒 =="
curl -s -X POST "$BASE/admin/keys" -H 'content-type: application/json' \
  -d '{"kid":"kid-demo-2","alg":"HS256","secret":"demo-signing-secret-0002"}' -o /dev/null
curl -s -X POST "$BASE/admin/keys/kid-demo-1/retire" -o /dev/null \
  -w "retire old key -> %{http_code}\n"
curl -s "$BASE/partner/consents/$CID" -H "authorization: Bearer $TOK" -o /dev/null \
  -w "old token after retire -> %{http_code} (expect 401)\n"
TOK2=$(curl -s -X POST "$BASE/partner/token" -H 'content-type: application/json' \
  -d '{"credential_id":"cred-tenant-a","secret":"partner-secret-a"}' | j "['access_token']")
curl -s -X POST "$BASE/partner/consents" -H "authorization: Bearer $TOK2" \
  -H 'content-type: application/json' -d '{"scopes":["balances"],"ttl_seconds":60}' \
  -o /dev/null -w "new token request -> %{http_code}\n"

echo "== 7) 审计记录（脱敏后）条数 =="
curl -s "$BASE/admin/audit?tenant_id=tenant-a" \
  | python3 -c "import sys,json;print('audit entries =',len(json.load(sys.stdin)['audit']))"

echo "演示完成。服务日志：/tmp/obg_demo.log"
