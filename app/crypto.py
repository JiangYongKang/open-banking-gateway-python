"""签名与哈希原语（本地实现，HMAC-SHA256，仅依赖标准库）。"""
from __future__ import annotations

import hashlib
import hmac


def hmac_sign(secret: bytes, message: bytes) -> bytes:
    """用 HMAC-SHA256 计算消息签名。"""
    return hmac.new(secret, message, hashlib.sha256).digest()


def hmac_verify(secret: bytes, message: bytes, signature: bytes) -> bool:
    """常量时间校验 HMAC 签名。"""
    expected = hmac_sign(secret, message)
    return constant_time_equals(expected, signature)


def constant_time_equals(a: bytes, b: bytes) -> bool:
    """hmac.compare_digest 包装，长度不同时同样安全返回 False。"""
    return hmac.compare_digest(a, b)


def hash_credential(secret: str) -> str:
    """对 API Key 明文做单向哈希后存储（SHA-256，本地实现）。"""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def mask_sensitive(value: str, keep: int = 4) -> str:
    """脱敏：保留末 keep 位，其余用 * 替换；短串整体掩码。"""
    if value is None:
        return ""
    text = str(value)
    if len(text) <= keep:
        return "*" * len(text)
    return "*" * (len(text) - keep) + text[-keep:]
