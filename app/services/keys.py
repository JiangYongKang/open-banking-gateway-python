"""密钥管理与轮换：新旧密钥并存、退役拒绝。"""
from __future__ import annotations

from app.errors import ErrorCode, GatewayError
from app.logging_utils import get_logger
from app.models import KeyState, SigningKey

logger = get_logger("keys")


class KeyService:
    def __init__(self, storage, audit, clock) -> None:  # noqa: ANN001
        self.storage = storage
        self.audit = audit
        self.clock = clock

    def add_key(self, kid: str, alg: str, secret: str) -> SigningKey:
        with self.storage.lock:
            if kid in self.storage.keys:
                raise GatewayError(ErrorCode.INTERNAL_ERROR,
                                   f"密钥已存在: {kid}", status_code=409)
            key = SigningKey(kid=kid, alg=alg, secret=secret,
                             state=KeyState.ACTIVE, created_at=self.clock.now())
            self.storage.keys[kid] = key
        self.audit.write("-", "key_add", "state_change", f"新增签名密钥 {kid} alg={alg}",
                         {"kid": kid, "alg": alg, "secret": secret})
        logger.info("key added kid=%s alg=%s", kid, alg)
        return key

    def rotate(self, new_kid: str, alg: str, new_secret: str, old_kid: str) -> SigningKey:
        """注册新活跃密钥并退役旧密钥；并存期间旧密钥已退役必须验签失败。

        典型轮换流程是先 add_key(new)（并存期）再 retire(old)；
        本方法为原子化的一步式轮换，供运维入口使用。
        """
        with self.storage.lock:
            self.add_key(new_kid, alg, new_secret)
            self.retire_key(old_kid)
            new_key = self.storage.keys[new_kid]
        logger.info("key rotated new=%s old=%s", new_kid, old_kid)
        return new_key

    def get_active_signing_key(self) -> SigningKey:
        with self.storage.lock:
            active = [k for k in self.storage.keys.values()
                      if k.state == KeyState.ACTIVE]
        if not active:
            raise GatewayError(ErrorCode.INTERNAL_ERROR, "无可用活跃签名密钥")
        # 最新创建的活跃密钥用于签发
        return sorted(active, key=lambda k: k.created_at)[-1]

    def retire_key(self, kid: str) -> SigningKey:
        with self.storage.lock:
            key = self.storage.keys.get(kid)
            if key is None:
                raise GatewayError(ErrorCode.TOKEN_KEY_UNKNOWN,
                                   f"未知密钥: {kid}", status_code=404)
            if key.state == KeyState.RETIRED:
                return key
            key.state = KeyState.RETIRED
            key.retired_at = self.clock.now()
        self.audit.write("-", "key_retire", "state_change", f"密钥退役 {kid}",
                         {"kid": kid})
        logger.info("key retired kid=%s", kid)
        return key

    def resolve_for_verify(self, kid: str) -> SigningKey:
        """验签取钥：未知 -> TOKEN_KEY_UNKNOWN；退役 -> TOKEN_KEY_RETIRED。"""
        with self.storage.lock:
            key = self.storage.keys.get(kid)
            if key is None:
                raise GatewayError(ErrorCode.TOKEN_KEY_UNKNOWN,
                                   f"未知签名密钥: {kid}")
            if key.state == KeyState.RETIRED:
                raise GatewayError(ErrorCode.TOKEN_KEY_RETIRED,
                                   f"签名密钥已退役: {kid}",
                                   details={"kid": kid, "retired_at": key.retired_at})
            return key

    def list_keys(self) -> list[SigningKey]:
        with self.storage.lock:
            return list(self.storage.keys.values())
