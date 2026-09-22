"""规模与超时上限中间件。

- 请求体超过 max_body_bytes：在读取业务处理前直接 413 拒绝，不进入任何业务逻辑，
  因此不会产生部分处理状态，也不消耗限流额度。
- 处理耗时超过 request_timeout_seconds：返回 408。业务侧均为锁内原子提交或
  失败回滚，超时拒绝不会留下半更新；中间件本身不持有跨请求锁/连接。
"""
from __future__ import annotations

import asyncio

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.errors import ErrorCode
from app.logging_utils import get_logger

logger = get_logger("middleware")


class LimitsMiddleware:
    def __init__(self, app: ASGIApp, max_body_bytes: int,
                 request_timeout_seconds: float) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.request_timeout_seconds = request_timeout_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 1) Content-Length 预检：超限直接拒绝，不读取 body、不进入业务
        declared = int(scope.get("headers") and
                       dict(scope.get("headers", [])).get(b"content-length", 0) or 0)
        if declared > self.max_body_bytes:
            await self._reject(send, ErrorCode.PAYLOAD_TOO_LARGE.value,
                               f"请求体超过上限 {self.max_body_bytes} 字节", 413,
                               {"limit_bytes": self.max_body_bytes,
                                "declared_bytes": declared})
            return

        # 2) 分块读取时的实际大小守卫
        received = 0

        async def guarded_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body_bytes:
                    raise _BodyTooLarge(received)
            return message

        # 3) 整体处理超时
        try:
            await asyncio.wait_for(
                self.app(scope, guarded_receive, send),
                timeout=self.request_timeout_seconds)
        except _BodyTooLarge as exc:
            logger.warning("body too large: %d bytes", exc.size)
            await self._reject(send, ErrorCode.PAYLOAD_TOO_LARGE.value,
                               f"请求体超过上限 {self.max_body_bytes} 字节", 413,
                               {"limit_bytes": self.max_body_bytes,
                                "received_bytes": exc.size})
        except (TimeoutError, asyncio.TimeoutError):
            logger.warning("request timeout after %.2fs",
                           self.request_timeout_seconds)
            await self._reject(send, ErrorCode.REQUEST_TIMEOUT.value,
                               f"请求处理超过 {self.request_timeout_seconds}s 上限",
                               408, {"timeout_seconds":
                                     self.request_timeout_seconds})

    @staticmethod
    async def _reject(send: Send, code: str, message: str, status: int,
                      details: dict) -> None:
        import json
        body = json.dumps({"error": {"code": code, "message": message,
                                     "details": details}}).encode("utf-8")
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


class _BodyTooLarge(Exception):
    def __init__(self, size: int) -> None:
        super().__init__("body too large")
        self.size = size
