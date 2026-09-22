"""访问令牌签名/验签原语与密钥轮换支持（本地 HMAC 实现）。

令牌格式：base64url(header).base64url(payload).base64url(signature)
- header: {"alg": "HS256", "kid": "...", "typ": "OBG1"}
- payload 为 TokenClaims 的 JSON
算法白名单由上层服务强制；本模块只负责编码、HMAC 与恒定时间比较。
"""
from __future__ import annotations

import base64
import hashlib
import hmac

from app.errors import ErrorCode, GatewayError
from app.models import TokenClaims


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _hmac_digest(secret: str, signing_input: bytes, alg: str) -> bytes:
    if alg == "HS256":
        return hmac.new(secret.encode("utf-8"), signing_input,
                        hashlib.sha256).digest()
    # 白名单在服务层判断；到达这里说明出现未实现的算法
    raise GatewayError(ErrorCode.TOKEN_ALG_NOT_ALLOWED,
                       f"不支持的签名算法: {alg}")


def sign(secret: str, signing_input: bytes, alg: str) -> bytes:
    return _hmac_digest(secret, signing_input, alg)


def constant_time_equals(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def issue_token(secret: str, alg: str, kid: str, claims: TokenClaims) -> str:
    import json

    header = {"alg": alg, "kid": kid, "typ": "OBG1"}
    payload = {
        "jti": claims.jti,
        "tenant_id": claims.tenant_id,
        "credential_id": claims.credential_id,
        "scopes": claims.scopes,
        "kid": kid,
        "alg": alg,
        "iat": claims.iat,
        "exp": claims.exp,
    }
    head = b64url_encode(json.dumps(header, separators=(",", ":"),
                                    sort_keys=True).encode("utf-8"))
    body = b64url_encode(json.dumps(payload, separators=(",", ":"),
                                    sort_keys=True).encode("utf-8"))
    signing_input = f"{head}.{body}".encode("ascii")
    sig = b64url_encode(sign(secret, signing_input, alg))
    return f"{head}.{body}.{sig}"


def inspect_token(token: str) -> dict:
    """仅解析结构（不验签），任何结构问题都归类为 MALFORMED_TOKEN。"""
    import json

    if not token or token.count(".") != 2:
        raise GatewayError(ErrorCode.MALFORMED_TOKEN, "令牌格式错误：应为三段式")
    head_b, body_b, _sig_b = token.split(".")
    try:
        header = json.loads(b64url_decode(head_b))
        payload = json.loads(b64url_decode(body_b))
    except Exception as exc:  # noqa: BLE001 - 解码/JSON 失败统一归类
        raise GatewayError(ErrorCode.MALFORMED_TOKEN,
                           "令牌无法解析") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise GatewayError(ErrorCode.MALFORMED_TOKEN, "令牌内容类型错误")
    return {"header": header, "payload": payload, "raw": token}
