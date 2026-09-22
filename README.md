# 多租户开放银行 API 接入层（本地可运行）

一个**纯本地**的开放银行网关参考实现：合作方按租户接入，网关统一完成
凭证/令牌校验、同意（Consent）状态流转、限流配额、回调幂等投递与审计落地；
银行与外部回调端全部用本地存储与本地模拟代替，**不依赖任何外部服务、真实凭据或付费资源**。

- 语言/框架：Python 3.14 + FastAPI（仅 fastapi/httpx/uvicorn 等仓库已有依赖）
- 存储：本地 JSON 文件（进程内锁 + `flock` + 临时文件原子替换 + 两阶段事务）
- 全部验证在本地完成：`uv run python -m unittest discover -s tests`

---

## 1. 快速开始

```bash
uv sync
uv run uvicorn app.main:app --reload          # http://127.0.0.1:8000  /docs 查看接口
# 一键业务演示（临时数据目录，自动起停服务）
./scripts/demo.sh 8090
```

管理面默认管理令牌 `X-Admin-Token: local-admin`（本地演示用）。

## 2. 租户接入方式

### 2.1 注册租户与合作方 API Key

```bash
# 注册
curl -X POST localhost:8090/admin/tenants -H "X-Admin-Token: local-admin" \
  -H 'Content-Type: application/json' -d '{"tenant_id":"acme","name":"ACME"}'

# 签发 API Key（明文凭据仅此一次返回，存储只保留 SHA-256 哈希）
curl -X POST localhost:8090/admin/tenants/acme/keys -H "X-Admin-Token: local-admin" \
  -H 'Content-Type: application/json' \
  -d '{"scopes":["accounts:read","callbacks:write","usage:read"],"ttl_seconds":3600}'
# => {"key_id":"kid-...", "secret":"sk-...", "record": {...}}
```

业务请求携带：

```
X-Tenant-Id: acme
X-API-Key:  kid-xxxx:sk-yyyy        # 形如 key_id:secret
# 或 Bearer 访问令牌（见 2.3）
Authorization: Bearer <token>
X-Tenant-Id: acme
```

凭证校验失败原因以**不同错误码**返回，绝不退化按其它租户继续处理：

| 场景 | error.code | HTTP |
|---|---|---|
| 缺少租户头/Key/Secret | `credential_missing` | 401 |
| key 不存在 / 不属于该租户 / 租户不存在 | `credential_unknown` | 401 |
| Secret 不匹配 | `credential_bad_secret` | 401 |
| 已吊销 | `credential_revoked` | 401 |
| 已过期 | `credential_expired` | 401 |
| 作用域不足 | `scope_insufficient` | 403 |
| 认证租户与路径租户不一致 | `auth_error` | 401 |

吊销：`DELETE /admin/tenants/{tid}/keys/{kid}`。

### 2.2 签名密钥轮换

```bash
POST /admin/tenants/{tid}/signing-keys                  # 新增 active 密钥，旧密钥并存
POST /admin/tenants/{tid}/signing-keys?retire_old=true  # 强制轮换：旧密钥全部退役
```

### 2.3 访问令牌（HMAC-SHA256 三段式，类似 JWT）

```bash
POST /admin/tenants/{tid}/tokens
  {"scopes":["accounts:read"], "ttl_seconds":3600, "key_id":"<可选，默认最新 active>"}
```

令牌校验按以下顺序给出**可区分结论**：

| 判定 | error.code |
|---|---|
| 结构非法 | `token_malformed` |
| `alg` 不在白名单（如 `none`） | `token_algorithm_not_allowed` |
| `kid` 在本租户密钥中不存在（不跨租户匹配） | `token_key_unknown` |
| `kid` 对应密钥已退役 | `token_key_retired` |
| 签名错误 | `token_bad_signature` |
| 已过期 | `token_expired` |

**轮换并存期**：新旧密钥都为 `active`，旧签名令牌正常通过，不被误拒；
执行 `retire_old=true` 后旧令牌得到明确的 `token_key_retired`。
算法白名单默认仅 `HS256`（`OBG_ALLOWED_ALGORITHMS` 可配）。

## 3. 同意（Consent）规则

状态机（非法流转返回 `consent_invalid_transition` / 409）：

```
PENDING ──authorise──▶ AUTHORISED ──revoke──▶ REVOKED   (终态)
   │                     │
   └──revoke─────────────┴──expire──▶ EXPIRED            (终态)
```

- 创建：`POST /admin/tenants/{tid}/consents`（resource + scopes + ttl_seconds）
- 授权：`POST .../consents/{cid}/authorise`（授权时确定 `expires_at`，并触发回调事件）
- 撤销：`POST .../consents/{cid}/revoke`（幂等的确定性事件 id：`evt-consent-{cid}`）
- 到期：后台/手动扫描 `POST /admin/tenants/{tid}/expire-consents`；
  即使扫描未运行，访问闸门在 TTL 到期时也会即时转 EXPIRED 并拒绝。

每次流转 `version += 1` 且向 `history` **仅追加**事件；终态后旧记录不可被覆盖。
资源访问 `GET /t/{tid}/accounts/{id}?consent_id=...` 的闸门结论：

| 场景 | error.code |
|---|---|
| 尚未授权 | `consent_not_authorised` |
| 已撤销 | `consent_revoked` |
| 已到期 | `consent_expired` |
| 同意资源 ≠ 请求资源 | `consent_resource_mismatch` |
| 同意不含所需 scope | `consent_scope_missing` |
| 同意不属于该租户 | `consent_not_found`（不泄漏存在性） |

## 4. 限流与配额规则

按 **租户 + 接口** 两级滑动窗口计数：

- 短窗限流 `rate`（默认 100 次 / 60s）与长窗配额 `quota`（默认 10000 次 / 天）。
- 超限返回 429，body 带 `details.retry_after`（秒）与 `limit_kind=rate|quota`，
  并返回标准 `Retry-After` 响应头。
- **被拒绝的请求不消耗额度**；先通过限流、随后被业务拒绝（如同意失效）的请求
  通过占位回滚也不消耗额度。可用 `GET /t/{tid}/usage?endpoint=...` 查询用量。
- 计数在文件锁事务内读改写，80 并发抢 20 名额时**恰好**放行 20（见并发测试）。

配置（环境变量）：`OBG_DEFAULT_RATE_LIMIT`、`OBG_DEFAULT_RATE_WINDOW_SECONDS`、
`OBG_DEFAULT_QUOTA`、`OBG_DEFAULT_QUOTA_WINDOW_SECONDS`。

## 5. 回调投递与重试策略

- 触发：`POST /t/{tid}/callbacks/trigger`（需 `callbacks:write`）。
  `event_id` 幂等：重复触发返回既有状态，不产生第二次投递（16 线程并发触发同一事件只投递 1 次）。
- 投递器（按租户配置 `PUT /admin/tenants/{tid}/webhook`）：
  - `{"mode":"local"}`：进程内受理，零网络（默认）；可设 `fail_times` 模拟前 N 次失败；
  - `{"mode":"http","url":"..."}`：httpx POST（可指向本服务 `/callbacks/receive` 做本地回环）。
- 退避：失败后按 `base * factor**(attempt-1)` 安排 `next_attempt_at`
  （默认 base=0.01s、factor=2）。可由后台工作线程自动重试
  （`OBG_ENABLE_RETRY_WORKER=1`），或手动 `POST /admin/retry-now`。
- 达到 `callback_max_attempts`（默认 5）后进入终态 `failed`，可通过
  `GET /admin/events/{event_id}` 查询状态、每次尝试日志与 `last_error`；
  每次尝试独立记账，重试不会污染其它事件。
- 载荷超过 `OBG_MAX_PAYLOAD_BYTES`（默认 64KB）返回 `callback_payload_too_large`，不落任何残留状态。

## 6. 审计

- 每次授权放行、拒绝与同意/密钥状态变更都写审计：`GET /admin/audit?tenant_id=...`。
- `secret`、`token`、`authorization`、`signature`、`password` 等敏感字段自动脱敏
  （保留末 4 位），API Key 明文不会出现在任何审计条目中。
- 审计为仅追加集合；状态变更与审计在同一事务，审计落盘失败时业务状态不会半更新。

## 7. 规模/超时上限配置

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `OBG_MAX_PAYLOAD_BYTES` | 65536 | 请求体/回调载荷上限，超限 413 拒绝 |
| `OBG_REQUEST_TIMEOUT_SECONDS` | 5.0 | 请求处理超时上限 |
| `OBG_UPSTREAM_TIMEOUT_SECONDS` | 2.0 | 模拟银行/HTTP webhook 调用超时，超时即快速失败 |
| `OBG_DEFAULT_CONSENT_TTL_SECONDS` | 3600 | 同意默认有效期 |
| `OBG_DATA_DIR` | `.local_data` | 本地 JSON 存储目录 |

失败路径不留部分处理状态（两阶段事务 + 幂等键），连接池与后台线程由 `Gateway.close()` 统一释放。

## 8. 本地验证方法

```bash
# 全部单测（27 个）：异常链路 + 并发竞争 + 真实本地 HTTP 回环
uv run python -m unittest discover -s tests -v

# 交互式演示
./scripts/demo.sh 8090
```

测试与服务日志（logger `obg.access` / `test.*`）会打印关键输入与判定依据，例如：

```
令牌判定 tenant=t1 token_head=... => status=401 code=token_key_retired
凭证判定输入 tenant_path=t2 headers={...} => code=credential_unknown
80 并发抢 20 名额: granted=20 rejected=60
16 并发触发同一事件: attempts=1 status=delivered sender_calls=1
```

测试文件覆盖：

| 文件 | 内容 |
|---|---|
| `tests/test_01_tenants_auth.py` | 凭证错误矩阵、越权跨租户、审计拒绝原因集合 |
| `tests/test_02_tokens_rotation.py` | 算法白名单、轮换并存、退役/未知 kid/签名错/过期 |
| `tests/test_03_consents.py` | 状态机全生命周期、非法流转、到期、历史不丢 |
| `tests/test_04_ratelimit_concurrency.py` | 80 线程竞争、被拒不耗额度、回滚、租户/接口隔离 |
| `tests/test_05_callbacks.py` | 幂等触发、退避重试、最终失败可查询、事件隔离 |
| `tests/test_06_audit_limits.py` | 脱敏、审计失败防半更新、载荷上限、超时与资源清理 |
| `tests/test_07_concurrency_idempotency.py` | 并发回调幂等、并发同意授权、uvicorn 本地 HTTP 回环投递 |

更多设计细节见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。
