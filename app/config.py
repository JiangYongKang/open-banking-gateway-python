"""网关可配置项：规模、超时、限流、回调退避等上限。

所有配置均可通过环境变量 OBG_* 覆盖，默认值保证本地开箱即用。
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    #: 本地 JSON 存储目录
    data_dir: str = ".local_data"
    #: 单次请求处理的超时上限（秒）
    request_timeout_seconds: float = 5.0
    #: 请求体大小上限（字节），超出直接拒绝（截断策略由入口执行）
    max_payload_bytes: int = 64 * 1024
    #: 默认每窗口限流次数（按租户+接口）
    default_rate_limit: int = 100
    default_rate_window_seconds: float = 60.0
    #: 默认每窗口配额次数（按租户+接口）
    default_quota: int = 10_000
    default_quota_window_seconds: float = 86_400.0
    #: 允许的令牌签名算法白名单
    allowed_algorithms: tuple[str, ...] = ("HS256",)
    #: 回调最大投递尝试次数（含首次）
    callback_max_attempts: int = 5
    callback_backoff_base_seconds: float = 0.01
    callback_backoff_factor: float = 2.0
    #: 同意默认有效期（秒）
    default_consent_ttl_seconds: float = 3600.0
    #: 模拟银行资源调用超时上限
    upstream_timeout_seconds: float = 2.0


def _env(name: str, default):
    raw = os.environ.get(f"OBG_{name}")
    if raw is None or raw == "":
        return default
    if isinstance(default, bool):
        return raw.lower() in ("1", "true", "yes")
    if isinstance(default, tuple):
        return tuple(item.strip() for item in raw.split(",") if item.strip())
    return type(default)(raw)


def load_settings() -> Settings:
    """从环境变量读取配置，缺省使用本地默认值。"""
    return Settings(
        data_dir=_env("DATA_DIR", Settings.data_dir),
        request_timeout_seconds=_env("REQUEST_TIMEOUT_SECONDS", Settings.request_timeout_seconds),
        max_payload_bytes=_env("MAX_PAYLOAD_BYTES", Settings.max_payload_bytes),
        default_rate_limit=_env("DEFAULT_RATE_LIMIT", Settings.default_rate_limit),
        default_rate_window_seconds=_env("DEFAULT_RATE_WINDOW_SECONDS", Settings.default_rate_window_seconds),
        default_quota=_env("DEFAULT_QUOTA", Settings.default_quota),
        default_quota_window_seconds=_env("DEFAULT_QUOTA_WINDOW_SECONDS", Settings.default_quota_window_seconds),
        allowed_algorithms=_env("ALLOWED_ALGORITHMS", Settings.allowed_algorithms),
        callback_max_attempts=_env("CALLBACK_MAX_ATTEMPTS", Settings.callback_max_attempts),
        callback_backoff_base_seconds=_env("CALLBACK_BACKOFF_BASE_SECONDS", Settings.callback_backoff_base_seconds),
        callback_backoff_factor=_env("CALLBACK_BACKOFF_FACTOR", Settings.callback_backoff_factor),
        default_consent_ttl_seconds=_env("DEFAULT_CONSENT_TTL_SECONDS", Settings.default_consent_ttl_seconds),
        upstream_timeout_seconds=_env("UPSTREAM_TIMEOUT_SECONDS", Settings.upstream_timeout_seconds),
    )
