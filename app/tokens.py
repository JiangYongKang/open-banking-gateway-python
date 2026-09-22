"""访问令牌签发与校验。

令牌为紧凑三段式（base64url(header).base64url(payload).base64url(sig)），
用 HMAC-SHA256 签名，语义类似 JWT 但仅依赖标准库。

校验时区分以下失败原因（不同错误码）：
  * token_malformed             结构/编码/JSON 非法
  * token_algorithm_not_allowed alg 不在白名单（即使签名能验过也拒绝）
  * token_key_unknown           kid 在本租户找不到（绝不回退尝试其它租户密钥）
  * token_key_retired           签名密钥已退役（轮换旧密钥退役后明确拒绝）
  * token_bad_signature         密钥有效但签名不匹配
  * token_expired               签名合法但已过期
"""
from __future__ import annotations

import base64
import json
import time

from .errors import (
    TokenBadSignatureError,
    TokenExpiredError,
    TokenKeyRetiredError,
    TokenKeyUnknownError,
    TokenMalformedError,
    TokenAlgorithmNotAllowedError,
)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def issue_token(
    secret: str | bytes,
    *,
    alg: str = "HS256",
    headers: dict | None = None,
    **claims,
) -> str:
    """用指定密钥与算法签发令牌。claims 中可放 iss/kid/scope/exp/iat/jti 等。"""
    header = {"alg": alg, "typ": "OBG-TOKEN"}
    if headers:
        header.update(headers)
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    payload_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    if alg == "HS256":
        from .crypto import hmac_sign

        signature = hmac_sign(secret.encode() if isinstance(secret, str) else secret, signing_input)
    else:
        raise ValueError(f"不支持的签发算法: {alg}")
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def _decode_part(part: str):
    try:
        return json.loads(_b64url_decode(part))
    except Exception:
        raise TokenMalformedError("令牌段无法解码")


def verify_token(
    token: str,
    keys_by_id: dict[str, "object"],
    *,
    allowed_algorithms: tuple[str, ...] = ("HS256",),
    now: float | None = None,
) -> dict:
    """校验令牌并返回 payload claims。

    keys_by_id: {kid: SigningKey-like}，每个对象需有 ``secret`` 与 ``status``
    （"active"/"retired"）属性。不同租户的 keys_by_id 必须分别传入，
    本函数绝不跨租户尝试密钥。
    """
    if not isinstance(token, str) or token.count(".") != 2:
        raise TokenMalformedError("令牌必须是三段式结构")
    header_b64, payload_b64, sig_b64 = token.split(".")

    header = _decode_part(header_b64)
    payload = _decode_part(payload_b64)
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise TokenMalformedError("令牌头或载荷不是 JSON 对象")
    try:
        signature = _b64url_decode(sig_b64)
    except Exception:
        raise TokenMalformedError("令牌签名段无法解码")

    alg = header.get("alg")
    kid = header.get("kid")
    if alg not in allowed_algorithms:
        # 算法白名单优先判定：不允许的算法（如 "none"、RS256）一律拒绝
        raise TokenAlgorithmNotAllowedError(f"算法 {alg!r} 不在白名单 {list(allowed_algorithms)}")
    if not isinstance(kid, str) or not kid:
        raise TokenMalformedError("令牌头缺少 kid")

    key = keys_by_id.get(kid)
    if key is None:
        raise TokenKeyUnknownError(f"密钥 {kid!r} 不存在")
    if getattr(key, "status", None) == "retired":
        raise TokenKeyRetiredError(f"密钥 {kid!r} 已退役")

    if alg == "HS256":
        from .crypto import hmac_verify

        secret = key.secret.encode() if isinstance(key.secret, str) else key.secret
        ok = hmac_verify(secret, f"{header_b64}.{payload_b64}".encode(), signature)
    else:  # pragma: no cover - 白名单已拦截，防御性分支
        raise TokenAlgorithmNotAllowedError(f"算法 {alg!r} 不支持")
    if not ok:
        raise TokenBadSignatureError("签名校验失败")

    exp = payload.get("exp")
    current = time.time() if now is None else now
    if exp is not None and float(exp) <= current:
        raise TokenExpiredError("访问令牌已过期")
    return payload
