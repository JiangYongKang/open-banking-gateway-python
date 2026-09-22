"""FastAPI 应用装配。"""
from __future__ import annotations

from fastapi import FastAPI

from app.api.deps import build_state
from app.api.middleware import LimitsMiddleware
from app.api.routes_admin import router as admin_router
from app.api.routes_partner import router as partner_router
from app.config import Settings, load_settings
from app.errors import register_exception_handlers


def create_app(settings: Settings | None = None, *, seed: bool = True) -> FastAPI:
    settings = settings or load_settings()
    app = FastAPI(title="Local Multi-Tenant Open Banking Gateway", version="0.1.0")

    app.state.obg = build_state(settings, seed=seed)

    app.add_middleware(LimitsMiddleware,
                       max_body_bytes=settings.max_body_bytes,
                       request_timeout_seconds=settings.request_timeout_seconds)
    register_exception_handlers(app)

    app.include_router(partner_router)
    app.include_router(admin_router)

    @app.get("/")
    def read_root() -> dict:
        return {"service": "open-banking-gateway", "status": "ok",
                "docs": "/docs", "health": "/admin/health"}

    return app


app = create_app()
