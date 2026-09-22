#!/usr/bin/env bash
# 本地一键演示：租户接入 -> 凭证校验 -> 同意流转 -> 限流 -> 回调投递 -> 审计查询
# 全程使用本地存储与本地 HTTP 回环，不依赖任何外部服务。
set -euo pipefail

PORT="${1:-8080}"
BASE="http://127.0.0.1:${PORT}"
ADMIN=(-H "X-Admin-Token: local-admin")
DATA_DIR="$(mktemp -d)"
SRV_PID=""
cleanup() { [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true; }
trap cleanup EXIT

echo "==> 使用临时数据目录 $DATA_DIR 启动网关"
OBG_DATA_DIR="$DATA_DIR" \
OBG_DEFAULT_RATE_LIMIT=3 OBG_DEFAULT_RATE_WINDOW_SECONDS=60 \
OBG_CALLBACK_MAX_ATTEMPTS=4 OBG_CALLBACK_BACKOFF_BASE_SECONDS=0.1 \
uv run uvicorn app.main:app --host 127.0.0.1 --port "$PORT" --log-level warning &
SRV_PID=$!

for _ in $(seq 1 50); do
  curl -sf "$BASE/health" >/dev/null && break
  sleep 0.1
done

j() { python3 -c "import sys,json;d=json.load(sys.stdin);print(eval(\"d$1\"))"; }

echo; echo "==> 1. 注册租户并签发 API Key"
curl -sS -X POST "$BASE/admin/tenants" "${ADMIN[@]}" -H 'Content-Type: application/json' \
  -d '{"tenant_id":"acme","name":"ACME 合作方"}' >/dev/null
KEY_JSON=$(curl -sS -X POST "$BASE/admin/tenants/acme/keys" "${ADMIN[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"scopes":["accounts:read","callbacks:write","usage:read"]}')
KID=$(echo "$KEY_JSON" | j "['key_id']")
SECRET=$(echo "$KEY_JSON" | j "['secret']")
echo "    key_id=$KID  secret=${SECRET:0:10}..."

echo; echo "==> 2. 无凭证访问被拒绝（credential_missing）"
curl -sS "$BASE/t/acme/accounts/acct-1?consent_id=x" | python3 -m json.tool

echo; echo "==> 3. 创建并授权同意"
CID=$(curl -sS -X POST "$BASE/admin/tenants/acme/consents" "${ADMIN[@]}" \
  -H 'Content-Type: application/json' \
  -d '{"resource":"acct-1","scopes":["accounts:read"],"ttl_seconds":3600}' | j "['consent_id']")
curl -sS -X POST "$BASE/admin/tenants/acme/consents/$CID/authorise" "${ADMIN[@]}" >/dev/null
echo "    consent_id=$CID 已授权"

echo; echo "==> 4. 持有效凭证 + 已授权同意访问账户（成功）"
curl -sS "$BASE/t/acme/accounts/acct-1?consent_id=$CID" \
  -H "X-Tenant-Id: acme" -H "X-API-Key: ${KID}:${SECRET}" | python3 -m json.tool

echo; echo "==> 5. 连续访问触发限流（rate=3），第 4 次返回 429 + Retry-After"
for i in 1 2 3 4; do
  code=$(curl -sS -o /tmp/obg-body -w "%{http_code}" "$BASE/t/acme/accounts/acct-1?consent_id=$CID" \
    -H "X-Tenant-Id: acme" -H "X-API-Key: ${KID}:${SECRET}")
  extra=""
  [ "$code" = "429" ] && extra=$(python3 -c "import json;print(json.load(open('/tmp/obg-body'))['error']['details'])")
  echo "    第 $i 次 -> HTTP $code $extra"
done

echo; echo "==> 6. 配置 webhook 前 2 次失败，触发回调后观察退避重试"
curl -sS -X PUT "$BASE/admin/tenants/acme/webhook" "${ADMIN[@]}" \
  -H 'Content-Type: application/json' -d '{"mode":"local","fail_times":2}' >/dev/null
curl -sS -X POST "$BASE/t/acme/callbacks/trigger" \
  -H "X-Tenant-Id: acme" -H "X-API-Key: ${KID}:${SECRET}" \
  -H 'Content-Type: application/json' \
  -d '{"event_id":"evt-demo-1","event_type":"payment.completed","payload":{"amount":"88.88"}}' \
  | python3 -m json.tool
echo "    等待退避后重试..."
sleep 0.35; curl -sS -X POST "$BASE/admin/retry-now" "${ADMIN[@]}" >/dev/null
sleep 0.35; curl -sS -X POST "$BASE/admin/retry-now" "${ADMIN[@]}" >/dev/null
curl -sS "$BASE/admin/events/evt-demo-1" "${ADMIN[@]}" | python3 -m json.tool

echo; echo "==> 7. 审计记录（敏感字段已脱敏）"
curl -sS "$BASE/admin/audit?tenant_id=acme" "${ADMIN[@]}" \
  | python3 -c "import sys,json;[print(f\"    {e['ts']:>12.0f} {e['result']:<12} {e['action']:<22} {e['detail'].get('reason','')}\") for e in json.load(sys.stdin)['entries']]"

echo; echo "演示完成。数据目录: $DATA_DIR"
