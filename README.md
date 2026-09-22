# 本地多租户开放银行 API 接入层（Open Banking Gateway）

一个**完全本地可运行**、无任何外部服务依赖的多租户开放银行接入层示例。用进程内存储
与本地模拟调用方替代真实银行、JWT 授权服务器与外部回调接收端，使以下能力在每个入口
（HTTP 接口、领域服务、运维接口）上都给出**一致且可解释**的结果：

- 合作方按租户接入与凭证校验（租户隔离、凭证状态、作用域）
- 访问令牌签名校验与密钥轮换（算法白名单、新旧密钥并存、退役拒绝）
- 同意（Consent）完整生命周期状态机（创建→授权→撤销/到期，历史只追加）
- 按租户 × 按接口的限流与日配额（并发不超发、拒绝不耗额度、返回等待秒数）
- 回调事件幂等投递、指数退避重试与可查询死信
- 全量审计落地，敏感字段脱敏，审计失败不产生静默半更新
- 可配置的请求体规模与处理超时上限，超限拒绝且无残留状态

> 仅用于本地开发、教学与测试。令牌为自包含的本地 HMAC 签名令牌（非生产级安全方案），
> 所有“银行/第三方”交互均为内存模拟。

## 目录结构

```
app/
  config.py             可配置上限/超时/限流/退避（支持 OBG_* 环境变量）
  errors.py             稳定错误码 + 统一结构化错误响应
  models.py             领域模型（凭证/密钥/令牌/同意/回调/审计）
  crypto.py             本地 HMAC 令牌签名与验签原语
  storage.py            线程安全内存存储 + JSON 原子落盘/恢复
  audit.py              审计落地、敏感字段脱敏、fail-open/fail-closed
  clock.py              可注入时钟（测试中推进时间验证过期/退避）
  simulator.py          本地模拟第三方调用方（成功/瞬时失败/永久失败）
  logging_utils.py      统一日志与脱敏工具
  services/             领域服务：keys / auth / consents / ratelimit / callbacks
  api/                  FastAPI 入口：路由、鉴权、中间件、序列化、依赖装配
  main.py               应用装配
tests/                  9+1 组共 61 个测试（异常链路 + 并发场景）
scripts/local_demo.sh   一键本地演示脚本
docs/                   详细设计与规则说明
```

## 快速开始

需要 Python ≥ 3.11（仓库固定 3.14），使用 [uv](https://docs.astral.sh/uv/)：

```bash
# 安装依赖（FastAPI + pytest，全部来自常规开源源）
uv sync

# 运行全部测试
uv run python -m pytest -q

# 启动服务（默认 http://127.0.0.1:8000 ，交互文档 /docs）
uv run uvicorn main:app --reload

# 或一键演示完整链路（令牌→同意→资源→撤销→回调→轮换→审计）
bash scripts/local_demo.sh
```

启动后自动播种两个演示租户与一把签名密钥：

| 租户 | credential_id | secret | 作用域 |
|------|---------------|--------|--------|
| tenant-a | `cred-tenant-a` | `partner-secret-a` | balances, transactions, payment, consent:manage |
| tenant-b | `cred-tenant-b` | `partner-secret-b` | balances, consent:manage |

签名密钥：`kid-demo-1` / HS256 / `demo-signing-secret-0001`

## 1. 租户接入方式

1. 合作方在 `/admin/credentials` 登记 `credential_id / tenant_id / secret / scopes / ttl`。
2. 用凭证向 `POST /partner/token` 换取 Bearer 访问令牌（携带租户、作用域、kid、alg、exp）。
3. 后续请求带 `Authorization: Bearer <token>`，网关依次执行：
   **令牌校验（算法白名单→密钥→签名→有效期→凭证状态）→租户隔离→作用域→限流**。

租户隔离是强制的：A 租户令牌访问 B 租户的同意/账户/回调一律 `403 tenant_mismatch`，
不会退化为以任意租户身份处理；无令牌或令牌无效一律 `401`，也不会放行。

凭证类拒绝原因互斥可区分：

| 场景 | HTTP | error.code |
|------|------|------------|
| 缺少凭证/令牌 | 401 | `missing_credentials` / `missing_token` |
| 未知凭证（租户） | 401 | `unknown_tenant` |
| 密钥不匹配 | 401 | `invalid_credential_secret` |
| 凭证已吊销 | 401 | `credential_revoked`（其已签发令牌同时失效） |
| 凭证已过期 | 401 | `credential_expired` |
| 跨租户访问 | 403 | `tenant_mismatch` |
| 作用域不足 | 403 | `scope_insufficient` |

## 2. 令牌签名与密钥轮换

- 令牌格式：`base64url(header).base64url(payload).base64url(signature)`，HMAC-SHA256。
- **算法白名单**：默认仅允许 `HS256`（`OBG_ALLOWED_ALGS` 可配）。`alg: none` 等返回
  `401 token_alg_not_allowed`。
- **密钥三态判定互不混淆**：
  - kid 不存在 → `token_key_unknown`
  - kid 已退役 → `token_key_retired`（即使签名正确也拒绝）
  - 密钥活跃但签名不符 → `token_bad_signature`
- **轮换流程**：`POST /admin/keys` 新增活跃密钥（与旧钥**并存**，旧令牌不误拒）→
  验证新令牌正常 → `POST /admin/keys/{old}/retire` 退役旧钥。
  也可用 `POST /admin/keys/rotate` 一步原子完成。

## 3. 同意（Consent）规则

状态机（非法流转返回 `409 consent_invalid_transition`）：

```
PENDING ──authorize──▶ AUTHORIZED ──revoke──▶ REVOKED   (终态)
   │                     │
   └──────revoke────────▶ REVOKED
   │                     │
   └────────expire──────▶ EXPIRED ◀──expire──┘           (终态)
```

- 每次流转都向 `history` **追加**一条 `{from,to,reason,actor,at}`，永不覆盖；撤销/到期
  记录完整保留。
- 资源访问（如 `GET /partner/accounts/{id}/balances?consent_id=...`）前强制校验：
  存在性→租户归属→状态（仅 AUTHORIZED 放行）→是否已过 `expires_at`→作用域→账户范围。
- 撤销后访问 → `403 consent_revoked`；到期后访问 → `403 consent_expired`
  （即使到期扫描尚未运行，超期同意也不放行）。
- 到期扫描：`POST /admin/consents/expire-due` 把所有过 `expires_at` 的同意置为 EXPIRED。

## 4. 限流与配额规则

- 维度：`(tenant_id, endpoint)` 的固定 60 秒窗口；另有按 `(tenant_id, UTC 日期)` 的日配额。
- 默认策略 `reject`：超限立即 `429 rate_limited_reject`，响应 `details` 带
  `limit_per_minute / current / retry_after_seconds / policy`。
- 可选策略 `delay`（`OBG_RATE_LIMIT_ACTION=delay`）：在 `delay_timeout_seconds` 内
  等待窗口重置后继续；超时返回 `429 rate_limited_timeout`。
- **被拒绝的请求（含等待超时、配额耗尽）不自增任何计数**；计数在存储锁内自增，
  并发下精确不超发（见 `tests/test_04_ratelimit.py`，50 线程抢 10 额度）。
- 细粒度配置：`rate_limit_per_minute` 的键形如 `"tenant-a:POST /partner/consents"`。

## 5. 回调投递与重试策略

- `POST /partner/callbacks/trigger` **幂等**：相同 `event_id` 重复触发只回显已有事件，
  绝不重复投递（并发重复触发同样安全，见压力测试）。
- 投递结果由本地模拟调用方按 URL 决定：
  - 普通 URL：成功
  - URL 含 `:transient:`：同一事件前两次失败、第三次成功
  - URL 以 `fail://` 开头：始终失败（用于验证退避与死信）
- 退避：第 n 次失败后等待 `backoff_base * backoff_factor^(n-1)`（默认 0.05s 起、翻倍）。
- 达到 `callback_max_attempts`（默认 5）仍失败 → `status=dead`，可通过
  `GET /partner/callbacks/{event_id}` 查询 `attempts / last_error / attempt_history`。
- 每个事件独立维护状态与历史，重试互不污染；退避时间未到时的重试请求返回 409。
- `POST /admin/callbacks/{event_id}/deliver` 用可注入时钟自动推进退避直到
  delivered/dead（本地验证用）。

## 6. 审计

- 每次授权（allowed）、拒绝（denied）、状态变更（state_change）都写一条结构化审计，
  可 `GET /admin/audit?tenant_id=...` 查询。
- `secret / token / signature / authorization / password` 等字段落盘前脱敏
  （默认仅留末尾 4 位）。
- 默认 fail-closed：审计文件写失败时业务流转**回滚**，不静默半更新
  （`tests/test_06_audit.py::test_audit_failure_rolls_back_business_state`）。
  `OBG_AUDIT_FAIL_OPEN=true` 可改为仅告警放行。

## 7. 规模 / 超时与资源

- `OBG_MAX_BODY_BYTES`（默认 64KiB）：超限在进入业务前返回 `413 payload_too_large`，
  不产生同意/令牌等任何部分状态，也不消耗限流额度。
- `OBG_REQUEST_TIMEOUT_SECONDS`（默认 5s）：超时返回 `408 request_timeout`。
- 服务端不持有跨请求连接/文件句柄：存储为内存表（可选一次性原子写盘），审计文件每次
  追加后即关闭；业务更新为锁内原子提交或失败回滚，不残留处理中间态。

## 8. 本地验证方法

```bash
uv run python -m pytest -q -s          # 全部测试；-s 可查看关键输入与判定日志
bash scripts/local_demo.sh            # 端到端 curl 演示
uv run uvicorn main:app --reload       # 手工调试：http://127.0.0.1:8000/docs
```

常用环境变量（均有本地默认值）：

| 变量 | 含义 | 默认 |
|------|------|------|
| `OBG_ALLOWED_ALGS` | 允许的签名算法 JSON 列表 | `["HS256"]` |
| `OBG_TOKEN_TTL_SECONDS` | 访问令牌有效期 | 300 |
| `OBG_RATE_LIMIT_DEFAULT_PER_MINUTE` | 每租户每接口每分钟上限 | 120 |
| `OBG_RATE_LIMIT_ACTION` | `reject` / `delay` | reject |
| `OBG_DELAY_TIMEOUT_SECONDS` | delay 最大等待 | 2.0 |
| `OBG_DAILY_QUOTA_DEFAULT` | 每租户日配额 | 10000 |
| `OBG_MAX_BODY_BYTES` | 请求体上限 | 65536 |
| `OBG_MAX_SCOPES` / `OBG_MAX_ACCOUNTS_PER_CONSENT` | 规模上限 | 50 / 100 |
| `OBG_REQUEST_TIMEOUT_SECONDS` | 请求处理超时 | 5.0 |
| `OBG_CALLBACK_MAX_ATTEMPTS` / `OBG_CALLBACK_BACKOFF_BASE` / `OBG_CALLBACK_BACKOFF_FACTOR` | 回调重试 | 5 / 0.05 / 2.0 |
| `OBG_PERSIST` / `OBG_STORAGE_PATH` / `OBG_AUDIT_PATH` | 落盘开关与路径 | false / data/… |
| `OBG_AUDIT_FAIL_OPEN` | 审计失败是否放行 | false |

## 9. 错误响应约定

所有错误统一为：

```json
{
  "error": {
    "code": "token_key_retired",
    "message": "签名密钥已退役: kid-demo-1",
    "details": {"kid": "kid-demo-1", "retired_at": 1790000000.0}
  }
}
```

完整错误码清单见 `app/errors.py`。
