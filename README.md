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

### 3.1 同意变更（追加作用域 / 延长有效期）

对**已授权生效**的同意，合作方可以申请变更；变更走独立的「变更单」两阶段流程，
不直接改动正在使用的授权：

```
POST /admin/tenants/{tid}/consents/{cid}/amendments
     {"add_scopes": ["payments:write"], "extend_seconds": 3600}
# => amendment_id，变更单进入 pending（待生效）

POST /admin/tenants/{tid}/amendments/{amendment_id}/approve   # 批准后才生效
```

规则（关键业务承诺）：

- **待生效期间一切照旧**：申请提交后、批准之前，同意的 `scopes` / `expires_at`
  不变、`version` 不增，资源访问闸门继续按当前生效版本放行，正在跑的业务不会被打断；
  即使变更里申请了新 scope，批准前用新 scope 访问仍得到 `consent_scope_missing`。
- **批准在单一跨集合事务内原子生效**：旧版本（scopes / expires_at / ttl / 版本号 /
  被哪个变更替换）完整快照写入同意的 `versions` 版本链，同意与变更单各自的
  `history` 都只增不改，旧版本永不被覆盖或丢失。
- 作用域变更按**并集去重**（不会丢旧作用域）；延期锚定「申请时的当前到期点 +
  extend_seconds」，审批延迟不会缩短有效期。仅延长有效期时 `ttl_seconds` 随之重算。
- **变更与撤销/到期撞车按最终状态算**：待生效期间同意被撤销或到期，变更单在
  **同一事务**内被置为 `void`（`void_reason = consent_revoked | consent_expired`），
  之后批准显式返回 `consent_amendment_void` / 409；撤销/到期之后任何 scope
  （包括申请追加的新 scope）都不可再读写。
- 同一同意同时只允许一个 `pending` 变更（`consent_amendment_conflict`）；
  对非 AUTHORISED 同意申请变更、申请无任何实际改动（scope 已包含且未延期）同样返回
  `consent_amendment_conflict`；重复批准是幂等的，不会产生第二个新版本。

## 3b. 同意动作批量提交与请求级幂等

合作方在业务面一次提交多条同意动作（`create` / `authorise` / `revoke` /
`amend_request` / `amend_approve` 可混合），并携带自己生成的 `request_id`：

```
POST /t/{tid}/consents/batch            # 需 scope: consents:write
{
  "request_id": "partner-uuid-0001",
  "actions": [
    {"action": "create", "resource": "acct-1",
     "scopes": ["accounts:read"], "ttl_seconds": 3600},
    {"action": "authorise", "consent_id": "consent-..."},
    {"action": "amend_request", "consent_id": "consent-...",
     "add_scopes": ["payments:write"], "extend_seconds": 1800},
    {"action": "amend_approve", "consent_id": "consent-...",
     "amendment_id": "amend-..."},
    {"action": "revoke", "consent_id": "consent-..."}
  ]
}
```

幂等约定与适用范围：

- 幂等作用域为 **租户 + request_id**（不同租户可复用相同字符串）。同一标识**全链路
  只真正执行一次**：首次之外的所有请求（包括首请求还在处理时就并发打进来的请求，
  无论来自同进程其它线程还是另一个进程）都会等待首个落定，随后拿到与首次
  **逐字节一致**的逐项结果，不会收到 `idempotency_in_progress` / 409 之类的中间态报错。
  重放一律 **不重复扣限流/配额、不重复触发回调、不重复改变状态**。
- **失败原子性（all-or-nothing）**：整批的全部动作、回调事件登记、审计与批次结果
  在**同一个跨集合事务**里一次落盘；若收尾阶段底层存储写入失败，正式文件一个都不会
  被替换——同意不会建出半成品、回调一条都不会发出。回调采用事务内 outbox：先随批
  事务幂等登记事件，事务成功后才做首次投递（投递失败走退避重试）。若执行者在落定
  前崩溃或落盘失败，该标识会停在 `processing`，**后续同 request_id 重试会自动接管
  执行**（进程崩溃时文件锁由内核释放），最终恰好完成一次并返回稳定结果，不会永久
  卡在“处理中/冲突”。
- 同一 `request_id` 但请求内容（动作列表）不同 → `idempotency_conflict` / 409。
- **逐项独立结果**：响应 `results[]` 每项带 `index / action / ok / consent_id /
  amendment_id / error{code,message}`，并给 `summary{total,succeeded,failed}`。
  单项非法（如对已撤销同意做变更 → `consent_amendment_conflict`、操作不存在的同意 →
  `consent_not_found`、未知动作 → `validation_error`）只让该一项失败并在批事务内
  回滚该项，不影响其它项，也**不会留下建了一半/算了一半的残留状态**。
- 单批最多 100 个动作；整批占用一次业务面限流配额（按接口
  `POST /consents/batch` 计），而不是按动作条数计。**只有唯一执行者占这 1 次**；
  完成后的重放与并发窗口里落败的请求一律占用 0 次（落败方在限流守卫之前等待并
  短路返回首次结果）。
- HTTP 层要求 scope `consents:write`；请求级幂等仅适用于该批量端点
  （回调的 `event_id` 幂等仍是各自独立的机制）。

## 3c. 合作方自助查询（只读）

```
GET /t/{tid}/consents/{cid}/insight     # 需 scope: consents:read
```

返回该同意的：当前概要（状态/作用域/各时间戳/版本）、`pending_amendment`
（若有待生效变更，含其目标作用域与目标到期点）、`recent_access[]`（近期**放行**
与各类**拒绝原因**：`revoked / expired / not_authorised / resource_mismatch /
scope_missing`，按时间倒序、默认最近 50 条）以及 `callbacks[]`（与该同意关联的
回调投递：授权、撤销、变更批准事件的投递状态/尝试次数/最后错误）。

- **严格租户隔离**：只能查本租户名下同意；查询他人同意与查询不存在的同意返回
  完全同形的 `consent_not_found` / 404，不泄漏存在性。
- **纯只读、零副作用**：该接口不写业务、不写审计、不经过限流配额，因此不会影响
  正常业务（如 `GET /accounts/{id}`）的用量口径（测试对查询前后计数做了断言）。

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
# 全部单测（68 个）：异常链路 + 并发竞争 + 多进程幂等 + 真实本地 HTTP 回环
uv run python -m unittest discover -s tests -v

# 只跑本次新增/相关能力（批量原子性、并发与故障恢复）
uv run python -m unittest tests.test_10_batch_idempotency \
    tests.test_12_amendment_races tests.test_13_batch_races_recovery -v

# 交互式演示
./scripts/demo.sh 8090
```

### 8.1 批量原子性 / 并发 / 配额口径的本地验证

`tests/test_13_batch_races_recovery.py` 用故障注入 + 屏障并发稳定复现以下场景，
可直接作为手工排查参考：

| 场景 | 测试 | 关键断言 |
|---|---|---|
| 收尾时底层存储写入失败 | `test_storage_failure_at_finalize_rolls_back_entire_batch` | 抛错后同意数不变、既有同意状态不变、回调集合为空、标识停 `processing` |
| 失败后同 request_id 重试 | 同上 | 首次重试完成（succeeded=2/failed=1），再重放结果逐字节一致；同意只建 1 个、回调只发 1 次（attempts=1、回执 1 条） |
| 中途暂存失败 | `test_storage_failure_mid_batch_all_or_nothing_then_retry` | 两个 create 一个都不落；重试后恰好 2 个，重放不产生第 3、4 个 |
| 24 线程同标识并发 | `test_threads_same_request_id_all_get_first_result` | 无任何异常；1 次执行 + 23 份一致重放；同意 2 个、回调 attempts=1 |
| 16 并发走完整 HTTP 栈 | `test_http_concurrent_same_request_id_quota_charged_once` | 全部 200、consent_id 全相同；`GET /usage` 恰为 `{rate:1,quota:1}`，完成后再重放仍为 1 |
| 重放不重发回调 | `test_replay_after_first_completes_does_not_resend_callback` | 5 次重放后回调仍 `delivered` / attempts=1 / 回执 1 条 |
| 两个独立进程同标识 | `CrossProcessBatchRaceTest` | 两个进程都成功、consent_id 相同、`{replayed: true, false}` 各一；落盘恰好 1 个同意 |

故障注入原理：`LocalStore.atomic` 先把涉及集合全部 stage 到同目录临时文件（含
`fsync`），全部成功后才依次 `os.replace`。测试把某集合的
`Collection._serialize_for_write` 替换成“第 N 次抛 `OSError`”，即可精确模拟
“业务都执行完、快要落定时磁盘突然失败”，此时正式 JSON 文件不会被替换。

手工压测可用同一 `request_id` 用 `curl`/`ab`/`wrk` 并发打
`POST /t/{tid}/consents/batch`，随后 `GET /t/{tid}/usage?endpoint=POST%20/consents%2Fbatch`
应恒为 `{"rate":1,"quota":1}`，`GET /admin/events/evt-consent-...` 的 `attempts` 恒为 1。

```bash
# 例：10 路并发同标识（xargs -P），观察返回的 consent_id 全部相同、replayed 仅一个 false
seq 10 | xargs -P10 -I{} curl -s -X POST localhost:8090/t/acme/consents/batch \
  -H 'X-Tenant-Id: acme' -H "X-API-Key: $K" -H 'Content-Type: application/json' \
  -d '{"request_id":"race-1","actions":[{"action":"create","resource":"acct-1","scopes":["accounts:read"],"ttl_seconds":3600}]}'
curl -s 'localhost:8090/t/acme/usage?endpoint=POST%20/consents%2Fbatch' -H 'X-Tenant-Id: acme' -H "X-API-Key: $K"
# => {"rate":1,"quota":1}
```

手工快速验证（服务起在 8090 后）：

```bash
A="X-Admin-Token: local-admin"
# 1) 创建并授权同意
CID=$(curl -s -X POST localhost:8090/admin/tenants/acme/consents -H "$A" -H 'Content-Type: application/json' \
  -d '{"resource":"acct-1","scopes":["accounts:read"],"ttl_seconds":3600}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["consent_id"])')
curl -s -X POST localhost:8090/admin/tenants/acme/consents/$CID/authorise -H "$A" >/dev/null
# 2) 申请变更（待生效，旧作用域仍可用），再批准（新作用域生效、旧版本入版本链）
AID=$(curl -s -X POST localhost:8090/admin/tenants/acme/consents/$CID/amendments -H "$A" -H 'Content-Type: application/json' \
  -d '{"add_scopes":["payments:write"],"extend_seconds":3600}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["amendment_id"])')
curl -s -X POST localhost:8090/admin/tenants/acme/amendments/$AID/approve -H "$A" | python3 -m json.tool
# 3) 批量 + 幂等（同 request_id 连打两次，第二次 replayed=true，用量只增 1）
curl -s -X POST localhost:8090/t/acme/consents/batch -H 'X-Tenant-Id: acme' -H "X-API-Key: $K" \
  -H 'Content-Type: application/json' -d '{"request_id":"demo-1","actions":[{"action":"revoke","consent_id":"'"$CID"'"}]}'
# 4) 自助查询：近期访问结论 + 关联回调（换别的租户查同 CID 得到 404 consent_not_found）
curl -s localhost:8090/t/acme/consents/$CID/insight -H 'X-Tenant-Id: acme' -H "X-API-Key: $K" | python3 -m json.tool
```

测试与服务日志（logger `obg.access` / `test.*`）会打印关键输入与判定依据，例如：

```
令牌判定 tenant=t1 token_head=... => status=401 code=token_key_retired
凭证判定输入 tenant_path=t2 headers={...} => code=credential_unknown
80 并发抢 20 名额: granted=20 rejected=60
16 并发触发同一事件: attempts=1 status=delivered sender_calls=1
16 并发同批：唯一执行 1 次，15 次拿到稳定重放结果
20 轮批准/撤销撞车：先批准后撤销=N 先撤销后拒批=M
跨进程并发同 request_id 结果=[{...replayed: true}, {...replayed: false}]
收尾写失败后：同意数=1（仅批外已有的 1 个，状态不变），回调=0，幂等记录=processing
失败后同标识重试完成：results 稳定一致，回调 attempts=1，回执=1
24 线程同 request_id：1 次执行 + 23 份一致重放，无 in_progress 报错
16 并发 HTTP 同单全部 200，用量={'rate': 1, 'quota': 1}（完成后重放仍为 1）
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
| `tests/test_09_consent_amendments.py` | 变更待生效不误伤、批准原子生效+版本链、撞撤销/到期作废、非法申请 |
| `tests/test_10_batch_idempotency.py` | 批量部分失败无残留、重放一致不扣额度/不重发回调、并发同批一次、租户作用域 |
| `tests/test_11_consent_insights.py` | 放行/拒绝原因视图、关联回调、跨租户 404、纯只读不碰用量与审计 |
| `tests/test_12_amendment_races.py` | 并发批准单次生效、批准/撤销撞车 20 轮可解释、跨进程 request_id 幂等 |
| `tests/test_13_batch_races_recovery.py` | 收尾存储写入失败整批回滚+同标识重试落定、24 线程并发全拿首次结果、HTTP 并发用量仅 1、跨进程并发双方都拿到稳定结果 |

更多设计细节见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。
