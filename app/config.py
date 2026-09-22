"""可配置的规模、超时与限流参数。

默认值保证本地零依赖即可运行；可通过 OBG_* 环境变量覆盖关键上限，
例如 OBG_MAX_BODY_BYTES / OBG_REQUEST_TIMEOUT_SECONDS /
OBG_RATE_LIMIT_DEFAULT_PER_MINUTE / OBG_RATE_LIMIT_ACTION。
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    # 令牌
    allowed_algs: list[str] = field(default_factory=lambda: ["HS256"])
    token_ttl_seconds: int = 300
    # 限流 / 配额：按 (租户, 接口) 维度，键形如 "tenant-a:GET /accounts"
    rate_limit_per_minute: dict[str, int] = field(default_factory=dict)
    rate_limit_default_per_minute: int = 120
    rate_limit_action: str = "reject"        # reject / delay
    delay_timeout_seconds: float = 2.0       # delay 策略最大等待
    # 配额
    daily_quota: dict[str, int] = field(default_factory=dict)
    daily_quota_default: int = 10000
    # 规模 / 超时上限
    max_body_bytes: int = 64 * 1024
    max_scopes: int = 50
    max_accounts_per_consent: int = 100
    request_timeout_seconds: float = 5.0
    # 回调重试退避：第 n 次失败后等待 base * factor**(n-1)
    callback_max_attempts: int = 5
    callback_backoff_base_seconds: float = 0.05
    callback_backoff_factor: float = 2.0
    # 存储与审计
    persist: bool = False
    storage_path: str = "data/gateway_state.json"
    audit_path: str = "data/audit.log"
    audit_fail_open: bool = False


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw not in (None, "") else default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    return float(raw) if raw not in (None, "") else default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


def _env_json(name: str, default):
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    return json.loads(raw)


def load_settings() -> Settings:
    """从环境变量加载配置；未设置时使用本地可运行的默认值。"""
    return Settings(
        allowed_algs=_env_json("OBG_ALLOWED_ALGS", ["HS256"]),
        token_ttl_seconds=_env_int("OBG_TOKEN_TTL_SECONDS", 300),
        rate_limit_per_minute=_env_json("OBG_RATE_LIMITS", {}),
        rate_limit_default_per_minute=_env_int("OBG_RATE_LIMIT_DEFAULT_PER_MINUTE", 120),
        rate_limit_action=os.environ.get("OBG_RATE_LIMIT_ACTION", "reject"),
        delay_timeout_seconds=_env_float("OBG_DELAY_TIMEOUT_SECONDS", 2.0),
        daily_quota=_env_json("OBG_DAILY_QUOTA", {}),
        daily_quota_default=_env_int("OBG_DAILY_QUOTA_DEFAULT", 10000),
        max_body_bytes=_env_int("OBG_MAX_BODY_BYTES", 64 * 1024),
        max_scopes=_env_int("OBG_MAX_SCOPES", 50),
        max_accounts_per_consent=_env_int("OBG_MAX_ACCOUNTS_PER_CONSENT", 100),
        request_timeout_seconds=_env_float("OBG_REQUEST_TIMEOUT_SECONDS", 5.0),
        callback_max_attempts=_env_int("OBG_CALLBACK_MAX_ATTEMPTS", 5),
        callback_backoff_base_seconds=_env_float("OBG_CALLBACK_BACKOFF_BASE", 0.05),
        callback_backoff_factor=_env_float("OBG_CALLBACK_BACKOFF_FACTOR", 2.0),
        persist=_env_bool("OBG_PERSIST", False),
        storage_path=os.environ.get("OBG_STORAGE_PATH", "data/gateway_state.json"),
        audit_path=os.environ.get("OBG_AUDIT_PATH", "data/audit.log"),
        audit_fail_open=_env_bool("OBG_AUDIT_FAIL_OPEN", False),
    )
