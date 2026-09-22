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
2. **状态与审计同事务**：同意流转与审计条目在 `storage.atomic` 两阶段事务中完成，
   序列化阶段任一失败则不 replace 任何正式文件，杜绝“业务已变但无审计”的半更新。
3. **限流原子性**：判定与计数在同一次文件锁事务内；超限分支在追加时间戳之前抛出，
   被拒请求零计数。业务随后拒绝（如同意失效）时通过 `Reservation.rollback()` 归还。
4. **回调幂等**：`event_id` 唯一；重试写回带 `attempts == 序号-1` 的乐观条件，
   并发尝试不会交叉污染；事件之间各自独立记录。
5. **资源管理**：httpx 连接池单例复用、网关 `close()` 统一释放；后台重试线程
   start/stop 幂等，可 join 退出。
