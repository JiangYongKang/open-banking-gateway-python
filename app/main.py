"""FastAPI 入口：组装全部本地接口。

入口分组：
* 管理面（/admin/*）：租户注册、凭证签发/吊销、密钥轮换、同意创建/授权/撤销、
  Webhook 配置、审计/回调查询。管理面用固定本地管理令牌（默认 "local-admin"）。
* 业务面（/t/{tenant_id}/...）：必须通过 API Key 或 Bearer Token 认证，
  带租户隔离、同意闸门与限流配额。

所有错误统一返回 ``{"error": {"code", "message", "tenant_id", ...}}``，
错误码稳定可区分；每个关键判定都会打印关键输入与依据（obg.access logger）。
"""
from __future__ import annotations

import logging
import os

from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager

from .config import Settings, load_settings
from .errors import (
    AuthError,
    CredentialMissingError,
    GatewayError,
    RateLimitError,
    ValidationError,
)
from .security import Principal, build_security_deps
from .tokens import issue_token

log = logging.getLogger("obg.access")

ADMIN_TOKEN_DEFAULT = "local-admin"


# ---------------------------------------------------------------- 请求模型

class RegisterTenantIn(BaseModel):
    tenant_id: str = Field(min_length=1)
    name: str = ""


class IssueKeyIn(BaseModel):
    scopes: list[str]
    ttl_seconds: float | None = None


class CreateConsentIn(BaseModel):
    resource: str
    scopes: list[str]
    ttl_seconds: float | None = None


class RequestAmendmentIn(BaseModel):
    add_scopes: list[str] = Field(default_factory=list)
    extend_ttl_seconds: float = 0.0


class BatchActionIn(BaseModel):
    action: str
    consent_id: str | None = None
    resource: str | None = None
    scopes: list[str] | None = None
    ttl_seconds: float | None = None
    add_scopes: list[str] | None = None
    extend_ttl_seconds: float | None = None


class BatchConsentsIn(BaseModel):
    actions: list[BatchActionIn] = Field(min_length=1)


class MintTokenIn(BaseModel):
    scopes: list[str]
    ttl_seconds: float = 3600.0
    key_id: str | None = None  # 指定用哪个签名 kid；缺省用最新 active


class WebhookIn(BaseModel):
    mode: str = "local"
    url: str | None = None
    fail_times: int = 0


class TriggerIn(BaseModel):
    event_id: str
    event_type: str
    payload: dict


class ReceiveIn(BaseModel):
    event_id: str
    event_type: str
    payload: dict


def create_app(settings: Settings | None = None, *, gateway=None) -> FastAPI:
    settings = settings or load_settings()
    from .runtime import Gateway

    gw = gateway or Gateway(settings)
    api_key_auth, bearer_auth = build_security_deps(
        gw.registry, settings, clock=gw.clock
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # 本地运行可打开后台重试：OBG_ENABLE_RETRY_WORKER=1
        enabled = os.environ.get("OBG_ENABLE_RETRY_WORKER", "")
        if enabled.lower() in ("1", "true", "yes"):
            gw.start_retry_worker()
        try:
            yield
        finally:
            gw.close()

    application = FastAPI(
        title="Local Open Banking Gateway", version="0.1.0", lifespan=lifespan
    )
    application.state.gateway = gw

    # ---------------------------------------------------- 错误处理与中间件

    @application.exception_handler(GatewayError)
    async def gateway_error_handler(request: Request, exc: GatewayError):
        body = {
            "error": {
                "code": exc.code,
                "message": exc.message,
                "tenant_id": exc.tenant_id,
            }
        }
        extras = {}
        if isinstance(exc, RateLimitError):
            extras["retry_after"] = exc.retry_after
            extras["limit_kind"] = exc.limit_kind
            extras["limit"] = exc.limit_config
        if extras:
            body["error"]["details"] = extras
        log.warning("拒绝 path=%s code=%s tenant=%s detail=%s",
                    request.url.path, exc.code, exc.tenant_id, extras or exc.message)
        headers = {}
        if isinstance(exc, RateLimitError):
            headers["Retry-After"] = f"{max(1, round(exc.retry_after))}"
        return JSONResponse(status_code=exc.status_code, content=body, headers=headers)

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=400,
            content={"error": {"code": "validation_error",
                               "message": "请求参数校验失败",
                               "tenant_id": None,
                               "details": exc.errors()}},
        )

    @application.middleware("http")
    async def enforce_payload_limit(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None and cl.isdigit() and int(cl) > settings.max_payload_bytes:
            log.warning("载荷超限 path=%s bytes=%s limit=%s",
                        request.url.path, cl, settings.max_payload_bytes)
            return JSONResponse(
                status_code=413,
                content={"error": {"code": "payload_too_large",
                                   "message": f"请求体超过 {settings.max_payload_bytes} 字节上限",
                                   "limit": settings.max_payload_bytes}},
            )
        return await call_next(request)

    # ------------------------------------------------------------ 管理面

    def require_admin(x_admin_token: str | None = Header(default=None)) -> str:
        expected = ADMIN_TOKEN_DEFAULT
        if x_admin_token != expected:
            raise CredentialMissingError("管理接口需要 X-Admin-Token")
        return "admin"

    @application.get("/health")
    def health():
        return {"status": "ok"}

    @application.post("/admin/tenants", dependencies=[Depends(require_admin)])
    def admin_register_tenant(body: RegisterTenantIn):
        return gw.registry.register_tenant(body.tenant_id, body.name)

    @application.post("/admin/tenants/{tenant_id}/keys", dependencies=[Depends(require_admin)])
    def admin_issue_key(tenant_id: str, body: IssueKeyIn):
        return gw.registry.issue_api_key(tenant_id, body.scopes, body.ttl_seconds)

    @application.delete(
        "/admin/tenants/{tenant_id}/keys/{key_id}", dependencies=[Depends(require_admin)]
    )
    def admin_revoke_key(tenant_id: str, key_id: str):
        gw.registry.revoke_api_key(tenant_id, key_id)
        return {"revoked": key_id}

    @application.post(
        "/admin/tenants/{tenant_id}/signing-keys", dependencies=[Depends(require_admin)]
    )
    def admin_rotate_key(tenant_id: str, retire_old: bool = False):
        return gw.registry.rotate_signing_key(tenant_id, retire_old=retire_old)

    @application.post(
        "/admin/tenants/{tenant_id}/tokens", dependencies=[Depends(require_admin)]
    )
    def admin_mint_token(tenant_id: str, body: MintTokenIn):
        """用租户当前签名密钥签发访问令牌（本地模拟授权服务器行为）。"""
        keys = gw.registry.get_signing_keys(tenant_id)
        active = [(k.kid, k) for k in keys.values() if k.status == "active"]
        if not active:
            raise ValidationError("租户尚无 active 签名密钥，请先轮换", tenant_id=tenant_id)
        if body.key_id is not None:
            chosen = next(((kid, k) for kid, k in active if kid == body.key_id), None)
            if chosen is None:
                raise ValidationError(
                    f"密钥 {body.key_id!r} 不存在或非 active", tenant_id=tenant_id
                )
        else:
            chosen = active[-1]
        kid, key = chosen
        now = gw.clock()
        token = issue_token(
            key.secret,
            headers={"kid": kid},
            iss=tenant_id,
            scope=body.scopes,
            iat=now,
            exp=now + body.ttl_seconds,
        )
        gw.audit.record(
            "token_mint", tenant_id=tenant_id, result="state_change",
            detail={"kid": kid, "scopes": body.scopes, "token": token},
        )
        return {"access_token": token, "token_type": "Bearer", "kid": kid,
                "expires_in": body.ttl_seconds}

    @application.post(
        "/admin/tenants/{tenant_id}/consents", dependencies=[Depends(require_admin)]
    )
    def admin_create_consent(tenant_id: str, body: CreateConsentIn):
        ttl = body.ttl_seconds or settings.default_consent_ttl_seconds
        return gw.consents.create(tenant_id, body.resource, body.scopes, ttl)

    @application.post(
        "/admin/tenants/{tenant_id}/consents/{consent_id}/authorise",
        dependencies=[Depends(require_admin)],
    )
    def admin_authorise_consent(tenant_id: str, consent_id: str):
        rec = gw.consents.authorise(tenant_id, consent_id)
        # 授权成功触发回调（事件 id 确定性派生，重复操作幂等）
        gw.callbacks.trigger(
            f"evt-consent-{consent_id}", tenant_id, "consent.authorised",
            {"consent_id": consent_id, "resource": rec["resource"]},
        )
        return rec

    @application.post(
        "/admin/tenants/{tenant_id}/consents/{consent_id}/revoke",
        dependencies=[Depends(require_admin)],
    )
    def admin_revoke_consent(tenant_id: str, consent_id: str):
        rec = gw.consents.revoke(tenant_id, consent_id)
        gw.callbacks.trigger(
            f"evt-consent-{consent_id}", tenant_id, "consent.revoked",
            {"consent_id": consent_id},
        )
        return rec

    @application.get(
        "/admin/tenants/{tenant_id}/consents/{consent_id}",
        dependencies=[Depends(require_admin)],
    )
    def admin_get_consent(tenant_id: str, consent_id: str):
        return gw.consents.get(tenant_id, consent_id)

    @application.post(
        "/admin/tenants/{tenant_id}/consents/{consent_id}/amendments/{amendment_id}/approve",
        dependencies=[Depends(require_admin)],
    )
    def admin_approve_amendment(tenant_id: str, consent_id: str, amendment_id: str):
        out = gw.consents.approve_amendment(tenant_id, consent_id, amendment_id)
        gw.callbacks.trigger(
            f"evt-consent-{consent_id}", tenant_id, "consent.amended",
            {"consent_id": consent_id, "amendment_id": amendment_id,
             "scopes": out["consent"]["scopes"],
             "expires_at": out["consent"]["expires_at"]},
        )
        return out

    @application.post(
        "/admin/tenants/{tenant_id}/consents/{consent_id}/amendments/{amendment_id}/reject",
        dependencies=[Depends(require_admin)],
    )
    def admin_reject_amendment(tenant_id: str, consent_id: str, amendment_id: str):
        return gw.consents.reject_amendment(tenant_id, consent_id, amendment_id)

    @application.post(
        "/admin/tenants/{tenant_id}/expire-consents", dependencies=[Depends(require_admin)]
    )
    def admin_expire(tenant_id: str):
        return {"expired": gw.consents.expire_due()}

    @application.put(
        "/admin/tenants/{tenant_id}/webhook", dependencies=[Depends(require_admin)]
    )
    def admin_configure_webhook(tenant_id: str, body: WebhookIn):
        return gw.sender.configure(
            tenant_id, mode=body.mode, url=body.url, fail_times=body.fail_times
        )

    @application.get("/admin/events/{event_id}", dependencies=[Depends(require_admin)])
    def admin_event_status(event_id: str):
        return gw.callbacks.status(event_id)

    @application.get("/admin/audit", dependencies=[Depends(require_admin)])
    def admin_audit(tenant_id: str | None = None):
        return {"entries": gw.audit.list(tenant_id)}

    @application.post("/admin/retry-now", dependencies=[Depends(require_admin)])
    def admin_retry_now():
        return {"attempted": gw.callbacks.run_due_retries()}

    # ------------------------------------------------------------ 业务面

    def _authenticate(
        required_scope: str,
        x_tenant_id: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ) -> Principal:
        """双入口认证：优先 Bearer，否则 API Key。两种方式都必须锁定到租户。"""
        if authorization:
            return bearer_auth(required_scope, x_tenant_id, authorization)
        return api_key_auth(required_scope, x_tenant_id, x_api_key)

    def _guarded(tenant_id: str, endpoint: str, fn):
        """限流守卫：fn 正常返回则提交占位；fn 抛错（含业务拒绝）则回滚占位。"""
        with gw.guard(tenant_id, endpoint) as g:
            result = fn()
            g.commit()
            return result

    @application.get("/t/{tenant_id}/accounts/{account_id}")
    def get_account(
        tenant_id: str,
        account_id: str,
        consent_id: str,
        x_tenant_id: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        principal = _authenticate(
            "accounts:read", x_tenant_id, x_api_key, authorization
        )
        if principal.tenant_id != tenant_id:
            raise AuthError("认证租户与路径租户不一致", tenant_id=tenant_id)
        endpoint = "GET /accounts/{id}"

        def _do():
            gw.consents.check_access(tenant_id, consent_id, account_id, "accounts:read")
            log.info("放行 tenant=%s endpoint=%s resource=%s principal=%s kid=%s",
                     tenant_id, endpoint, account_id, principal.kind, principal.key_id)
            data = gw.bank.get_account(account_id)
            gw.audit.record(
                "resource_access", tenant_id=tenant_id, result="allowed",
                detail={"resource": account_id, "consent_id": consent_id,
                        "principal": principal.kind, "key_id": principal.key_id},
            )
            return data

        return _guarded(tenant_id, endpoint, _do)

    @application.post("/t/{tenant_id}/callbacks/trigger")
    def trigger_event(
        tenant_id: str,
        body: TriggerIn,
        x_tenant_id: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        principal = _authenticate("callbacks:write", x_tenant_id, x_api_key, authorization)
        if principal.tenant_id != tenant_id:
            raise AuthError("认证租户与路径租户不一致", tenant_id=tenant_id)
        endpoint = "POST /callbacks/trigger"
        return _guarded(
            tenant_id, endpoint,
            lambda: gw.callbacks.trigger(body.event_id, tenant_id, body.event_type, body.payload),
        )

    @application.post("/callbacks/receive")
    def receive_webhook(body: ReceiveIn, x_event_id: str | None = Header(default=None)):
        """本地 webhook 接收端（http 模式的对端就是它），按 event_id 幂等受理。"""
        incoming = x_event_id or body.event_id
        log.info("webhook 受理 event_id=%s type=%s", incoming, body.event_type)
        return {"accepted": True, "event_id": incoming}

    @application.get("/t/{tenant_id}/usage")
    def usage(
        tenant_id: str,
        endpoint: str = "GET /accounts/{id}",
        x_tenant_id: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        _authenticate("usage:read", x_tenant_id, x_api_key, authorization)
        return gw.limiter.usage(tenant_id, endpoint, gw.default_limits())

    # ------------------------------------------------ 同意变更（合作方自助）

    @application.post("/t/{tenant_id}/consents/{consent_id}/amendments")
    def request_amendment(
        tenant_id: str,
        consent_id: str,
        body: RequestAmendmentIn,
        x_tenant_id: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        principal = _authenticate("consents:write", x_tenant_id, x_api_key, authorization)
        if principal.tenant_id != tenant_id:
            raise AuthError("认证租户与路径租户不一致", tenant_id=tenant_id)
        endpoint = "POST /consents/{id}/amendments"

        def _do():
            return gw.consents.request_amendment(
                tenant_id, consent_id,
                add_scopes=body.add_scopes,
                extend_ttl_seconds=body.extend_ttl_seconds,
            )

        return _guarded(tenant_id, endpoint, _do)

    # ------------------------------------------- 同意动作批量（请求级幂等）

    @application.post("/t/{tenant_id}/consent-actions/batch")
    def batch_consents(
        tenant_id: str,
        body: BatchConsentsIn,
        idempotency_key: str | None = Header(default=None),
        x_tenant_id: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        """一次提交多条同意动作；同 Idempotency-Key 重放只返回首次稳定结果。"""
        principal = _authenticate("consents:write", x_tenant_id, x_api_key, authorization)
        if principal.tenant_id != tenant_id:
            raise AuthError("认证租户与路径租户不一致", tenant_id=tenant_id)
        endpoint = "POST /consent-actions/batch"
        # 先做整批形态校验（空批次/未知动作）：整批非法时不占额度
        actions = gw.batch.validate_actions(
            [a.model_dump(exclude_none=True) for a in body.actions]
        )
        from .batch import _fingerprint

        # 重放在占额度之前短路：同键等价请求直接返回首次稳定结果，
        # 不重复扣额度、不重复执行、不重复发回调。
        replay = gw.batch.lookup_replay(
            tenant_id, idempotency_key, _fingerprint(actions)
        )
        if replay is not None:
            return replay

        def _fire_batch_callbacks(events):
            for ev in events:
                cid = ev["consent_id"]
                if ev["kind"] == "authorise":
                    gw.callbacks.trigger(
                        f"evt-consent-{cid}", tenant_id, "consent.authorised",
                        {"consent_id": cid, "resource": ev.get("resource")},
                    )
                elif ev["kind"] == "revoke":
                    gw.callbacks.trigger(
                        f"evt-consent-{cid}", tenant_id, "consent.revoked",
                        {"consent_id": cid},
                    )

        def _do():
            return gw.batch.execute(
                tenant_id, idempotency_key, actions,
                on_committed=_fire_batch_callbacks,
            )

        return _guarded(tenant_id, endpoint, _do)

    # --------------------------------------------- 同意自助只读视图（本租户）

    def _view_auth(
        tenant_id: str, x_tenant_id, x_api_key, authorization, required_scope="consents:read"
    ):
        principal = _authenticate(required_scope, x_tenant_id, x_api_key, authorization)
        if principal.tenant_id != tenant_id:
            raise AuthError("认证租户与路径租户不一致", tenant_id=tenant_id)
        return principal

    @application.get("/t/{tenant_id}/consents/{consent_id}/view")
    def consent_overview(
        tenant_id: str,
        consent_id: str,
        limit: int = 50,
        x_tenant_id: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        _view_auth(tenant_id, x_tenant_id, x_api_key, authorization)
        # 纯只读：不经限流守卫、不写审计，不影响业务用量口径
        return gw.views.overview(tenant_id, consent_id, limit=limit)

    @application.get("/t/{tenant_id}/consents/{consent_id}/access-results")
    def consent_access_results(
        tenant_id: str,
        consent_id: str,
        limit: int = 50,
        x_tenant_id: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        _view_auth(tenant_id, x_tenant_id, x_api_key, authorization)
        return gw.views.access_results(tenant_id, consent_id, limit=limit)

    @application.get("/t/{tenant_id}/consents/{consent_id}/callbacks")
    def consent_callback_deliveries(
        tenant_id: str,
        consent_id: str,
        limit: int = 50,
        x_tenant_id: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
    ):
        _view_auth(tenant_id, x_tenant_id, x_api_key, authorization)
        return gw.views.callback_deliveries(tenant_id, consent_id, limit=limit)

    return application


# 模块级应用（uvicorn app.main:app）
app = create_app()
