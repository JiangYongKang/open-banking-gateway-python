"""合作方入口：令牌签发、同意全生命周期、模拟资源访问、回调触发与查询。

所有资源型接口都要：Bearer 令牌校验（含算法白名单/密钥轮换/有效期）、
租户隔离、作用域检查与按租户/接口的限流。
"""
from __future__ import annotations

from fastapi import APIRouter, Header, Request

from app.api import serializers
from app.api.deps_auth import authorize
from app.api.schemas import (
    CallbackTriggerRequest,
    ConsentCreateRequest,
    RevokeRequest,
    TokenRequest,
)
from app.errors import ErrorCode, GatewayError

router = APIRouter(prefix="/partner", tags=["partner"])


@router.post("/token")
def issue_token(body: TokenRequest, request: Request) -> dict:
    state = request.app.state.obg
    # 令牌签发本身也纳入按租户的限流（凭证校验通过才能确定租户）
    token, claims = state.auth.issue_access_token(body.credential_id, body.secret)
    state.ratelimit.acquire(claims.tenant_id, "POST /partner/token")
    return {"access_token": token, "token_type": "Bearer",
            "expires_in": int(claims.exp - claims.iat),
            "tenant_id": claims.tenant_id, "scopes": claims.scopes}


@router.post("/consents")
def create_consent(body: ConsentCreateRequest, request: Request,
                   authorization: str = Header(default="", alias="Authorization")) -> dict:
    claims = authorize(request, authorization, ["consent:manage"])
    state = request.app.state.obg
    consent = state.consents.create(claims.tenant_id, body.scopes,
                                    body.account_ids, body.ttl_seconds)
    return serializers.consent_out(consent)


@router.post("/consents/{consent_id}/authorize")
def authorize_consent(consent_id: str, request: Request,
                      authorization: str = Header(default="", alias="Authorization")) -> dict:
    claims = authorize(request, authorization, ["consent:manage"])
    state = request.app.state.obg
    consent = state.consents.authorize(claims.tenant_id, consent_id)
    return serializers.consent_out(consent)


@router.post("/consents/{consent_id}/revoke")
def revoke_consent(consent_id: str, body: RevokeRequest, request: Request,
                   authorization: str = Header(default="", alias="Authorization")) -> dict:
    claims = authorize(request, authorization, ["consent:manage"])
    state = request.app.state.obg
    consent = state.consents.revoke(claims.tenant_id, consent_id, body.reason)
    return serializers.consent_out(consent)


@router.get("/consents/{consent_id}")
def get_consent(consent_id: str, request: Request,
                authorization: str = Header(default="", alias="Authorization")) -> dict:
    claims = authorize(request, authorization, ["consent:manage"])
    state = request.app.state.obg
    consent = state.consents.get(claims.tenant_id, consent_id)
    return serializers.consent_out(consent)


@router.get("/accounts/{account_id}/balances")
def get_balances(account_id: str, request: Request, consent_id: str = "",
                 authorization: str = Header(default="", alias="Authorization")) -> dict:
    # 资源接口要求 balances 作用域；同意本身的作用域/账户/状态由同意服务判定
    claims = authorize(request, authorization, ["balances"])
    state = request.app.state.obg
    if not consent_id:
        raise GatewayError(ErrorCode.CONSENT_NOT_FOUND,
                           "缺少 consent_id 查询参数", status_code=400)
    state.consents.get_for_access(claims.tenant_id, consent_id,
                                  scope="balances", account_id=account_id)
    # 本地模拟银行返回（不访问真实银行）
    return {"account_id": account_id, "currency": "CNY",
            "balance": "10000.00", "served_by": "local-simulated-bank",
            "consent_id": consent_id, "tenant_id": claims.tenant_id}


@router.post("/callbacks/trigger")
def trigger_callback(body: CallbackTriggerRequest, request: Request,
                     authorization: str = Header(default="", alias="Authorization")) -> dict:
    claims = authorize(request, authorization, ["consent:manage"])
    state = request.app.state.obg
    event = state.callbacks.trigger(claims.tenant_id, body.event_id,
                                    body.callback_url, body.payload)
    return serializers.event_out(event)


@router.get("/callbacks/{event_id}")
def get_callback(event_id: str, request: Request,
                 authorization: str = Header(default="", alias="Authorization")) -> dict:
    claims = authorize(request, authorization, ["consent:manage"])
    state = request.app.state.obg
    event = state.callbacks.get_owned(claims.tenant_id, event_id)
    return serializers.event_out(event)
