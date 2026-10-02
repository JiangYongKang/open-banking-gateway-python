# 架构与模块说明

```
app/
├── config.py     可配置上限（规模/超时/限流/退避/算法白名单），环境变量 OBG_* 覆盖
├── errors.py     稳定错误码体系（每种拒绝原因一个 code + HTTP 状态码）
├── crypto.py     HMAC-SHA256、常量时间比较、凭证哈希、敏感字段脱敏
├── storage.py    本地 JSON 存储：文件锁 flock + 线程锁；两阶段提交的跨集合事务
├── models.py     同意状态机（合法流转表）
├── tokens.py     访问令牌签发/校验（算法白名单/kid/签名/过期，原因可区分）
├── tenants.py    租户注册、API Key 签发/吊销/校验、签名密钥轮换
├── consents.py   同意生命周期（创建→授权→撤销/到期），历史仅追加
├── amendments.py 同意变更（追加作用域/延期）：待生效→批准/作废，版本链只增不改
├── batch.py      同意动作批量提交 + 请求级幂等（租户+request_id 作用域）
├── insights.py   合作方自助只读视图：近期访问结论 + 关联回调，严格租户隔离
├── ratelimit.py  两级滑动窗口（rate 短窗 + quota 长窗），Reservation 可回滚
├── callbacks.py  回调幂等触发、指数退避重试、delivered/failed 终态
├── audit.py      审计构造与落地，secret/token 等字段脱敏
├── resources.py  本地模拟银行（账户/交易），含延迟/超时模拟
├── security.py   FastAPI 依赖：API Key 与 Bearer Token 两套认证
├── runtime.py    组装根 Gateway、LocalWebhookSender、后台重试线程
└── main.py       HTTP 入口（管理面 /admin，业务面 /t/{tenant_id}）
```

## 关键一致性设计

1. **租户隔离**：凭证 `key_id` 全局唯一，校验必须同时匹配
   `X-Tenant-Id` 与凭证归属租户；令牌只在“当前租户的密钥集合”中查 kid。
   任何不匹配都直接拒绝，不会回退尝试其它租户。
2. **状态与审计同事务**：同意流转、变更批准/作废与审计条目在 `storage.atomic` 两阶段事务中完成，
   序列化阶段任一失败则不 replace 任何正式文件，杜绝“业务已变但无审计”的半更新。
3. **变更不打断在用授权，版本链只增不改**：变更申请只写 `amendments` 集合（待生效），
   绝不在中途改 `consents` 的 scopes/expires_at；批准时在 **consents + amendments + audit**
   同一事务内把旧版本完整快照追加进 `consent.versions`，再切换到新版本。同意在变更待生效期间
   进入 REVOKED/EXPIRED 时，终态化事务会同时把其 pending 变更单置 `void`
   （`consents.py` 通过 `amendment_void_hook` 调用 `amendments.void_pending_in_tx`），
   因此“先撤销/到期、后批准”在同一事务里就被否决，新作用域在终态后永不可用。
4. **批量整批原子 + 请求级幂等**：占位判定、全部动作执行、幂等结果记录与回调登记
   在 **同一个跨集合事务**（consents + amendments + callbacks + audit + idempotency，
   `store.atomic` 两阶段提交：先把全部集合 stage 成临时文件，再统一原子 rename）里完成。
   收尾阶段底层存储写入失败（含 fsync/序列化异常）时正式文件一个都不会被替换——
   同意不建不改、回调不发、幂等记录也不会停在 processing，同 request_id 重试即为
   全新的首次执行。事务内每项动作跑在自己的深拷贝快照上：成功项的快照逐级累积，
   失败项仅保留其 denied 审计、业务改动整体丢弃，因此单项失败不污染其它项、无残留。
   回调采用**事务性 outbox**：事件在大事务内登记为 pending，提交成功后才首次投递；
   回滚则记录不存在、绝不发出；提交后投递前崩溃由
   `CallbackDispatcher.recover_undelivered()`（后台重试线程每轮调用）补投。
   幂等以「租户 | request_id」为键存入 `idempotency` 集合，只持久化 completed 终态；
   指纹（动作列表规范化 JSON 的 SHA-256）不一致返回 `idempotency_conflict`。
   并发提交同一 request_id 时，进程内由每键锁串行、跨进程由大事务上的 flock 串行，
   落败方在锁释放后看到的必是 completed 记录，直接返回首次结果，绝不向合作方暴露
   “处理中/冲突”中间态；旧版本遗留的 processing 卡死占位会被新请求接管重跑。
   HTTP 层在限流守卫**之前**先查重，使幂等重放不扣额度；并发窗口内先进入守卫、
   随后才发现自己是落败重放的请求，会在返回前归还限流占位——整批只有首次执行计
   1 次，任何重放（含并发重放、失败请求）均为 0 占用。
5. **自助视图纯只读**：`insights.py` 只调用 `Collection.list_items()` 快照读并按 tenant_id
   过滤，跨租户与不存在统一抛 `consent_not_found`；不写审计、不过限流，故不污染用量口径。
6. **限流原子性**：判定与计数在同一次文件锁事务内；超限分支在追加时间戳之前抛出，
   被拒请求零计数。业务随后拒绝（如同意失效）时通过 `Reservation.rollback()` 归还。
7. **回调幂等**：`event_id` 唯一；重试写回带 `attempts == 序号-1` 的乐观条件，
   并发尝试不会交叉污染；事件之间各自独立记录。
8. **资源管理**：httpx 连接池单例复用、网关 `close()` 统一释放；后台重试线程
   start/stop 幂等，可 join 退出。

## 新增持久化集合

| 集合 | 键 | 内容 |
|---|---|---|
| `amendments` | `amend-<hex>` | 变更单：状态 pending/approved/void、base/result 快照、extend、版本基号、仅追加 history |
| `idempotency` | `<tenant>\|<request_id>` | 批量幂等记录：指纹、completed 终态（processing 不再持久化）、首次完整逐项结果与摘要 |
| `callbacks` | `evt-...` | 回调事件（含批量 outbox 登记）：pending/delivered/failed、尝试日志与退避时间 |

`consents` 记录新增 `versions`（旧版本完整快照链）。所有集合沿用同一套 flock +
两阶段事务。整批提交把业务集合与 idempotency 结果放进同一个两阶段事务，因此不会
再出现“业务已生效但批次记录卡在 processing”的中间态；同一 request_id 的并发
（含跨进程）落败方等待首个事务提交后直接读取 completed 结果。
