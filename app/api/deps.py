"""共享状态装配与依赖注入。

一个 AppState 聚合存储、审计、时钟、模拟调用方与全部领域服务；
路由通过 FastAPI 的 app.state 取用，测试可注入自定义 Settings/Clock。
"""
from __future__ import annotations

from fastapi import Request

from app.audit import AuditLog
from app.clock import Clock
from app.config import Settings, load_settings
from app.simulator import SimulatedCaller
from app.services.auth import AuthService
from app.services.callbacks import CallbackService
from app.services.consents import ConsentService
from app.services.keys import KeyService
from app.services.ratelimit import RateLimitService
from app.storage import Storage


class AppState:
    def __init__(self, settings: Settings | None = None, *, seed: bool = True) -> None:
        self.settings = settings or load_settings()
        self.clock = Clock()
        self.storage = Storage()
        self.audit = AuditLog(path=self.settings.audit_path if self.settings.persist
                              else "", fail_open=self.settings.audit_fail_open)
        self.caller = SimulatedCaller()

        self.keys = KeyService(self.storage, self.audit, self.clock)
        self.auth = AuthService(self.storage, self.audit, self.keys,
                                self.settings, self.clock)
        self.consents = ConsentService(self.storage, self.audit,
                                       self.settings, self.clock)
        self.ratelimit = RateLimitService(self.storage, self.settings, self.clock)
        self.callbacks = CallbackService(self.storage, self.audit, self.settings,
                                         self.clock, self.caller)

        if self.settings.persist:
            self.storage.load(self.settings.storage_path)
        if seed:
            self._seed_demo_data()

    def _seed_demo_data(self) -> None:
        """写入本地演示用密钥/租户凭证，便于开箱验证。"""
        if self.storage.keys:
            return
        self.keys.add_key("kid-demo-1", "HS256", "demo-signing-secret-0001")
        self.auth.register_credential(
            "cred-tenant-a", "tenant-a", "partner-secret-a",
            ["balances", "transactions", "payment", "consent:manage"])
        self.auth.register_credential(
            "cred-tenant-b", "tenant-b", "partner-secret-b",
            ["balances", "consent:manage"])

    def reset(self) -> None:
        self.storage.reset()
        self.audit.reset()
        self.caller.reset()
        self.clock.reset()
        self._seed_demo_data()


def build_state(settings: Settings | None = None, *, seed: bool = True) -> AppState:
    return AppState(settings, seed=seed)


def get_state(request: Request) -> AppState:
    return request.app.state.obg
