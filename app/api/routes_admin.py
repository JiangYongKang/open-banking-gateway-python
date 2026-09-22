"""运维/本地测试入口：凭证管理、密钥轮换、同意到期扫描、回调推进、审计查询。

这些入口仅用于本地接入与验证，不要求合作方 Bearer 令牌；生产环境应由独立
运维鉴权保护。返回内容中的敏感字段已在审计层脱敏。
"""
from __future__ import annotations

from fastapi import APIRouter, Request

from app.api import serializers
from app.api.schemas import CredentialRegisterRequest, KeyAddRequest, KeyRotateRequest

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/credentials")
def register_credential(body: CredentialRegisterRequest, request: Request) -> dict:
    state = request.app.state.obg
    cred = state.auth.register_credential(
        body.credential_id, body.tenant_id, body.secret, body.scopes,
        ttl_seconds=body.ttl_seconds)
    return serializers.credential_out(cred)


@router.post("/credentials/{credential_id}/revoke")
def admin_revoke_credential(credential_id: str, request: Request) -> dict:
    state = request.app.state.obg
    state.auth.revoke_credential(credential_id)
    return {"credential_id": credential_id, "revoked": True}


@router.post("/keys")
def add_key(body: KeyAddRequest, request: Request) -> dict:
    state = request.app.state.obg
    key = state.keys.add_key(body.kid, body.alg, body.secret)
    return serializers.key_out(key)


@router.post("/keys/rotate")
def rotate_key(body: KeyRotateRequest, request: Request) -> dict:
    state = request.app.state.obg
    state.keys.rotate(body.new_kid, body.alg, body.new_secret, body.old_kid)
    return {"new_kid": body.new_kid, "old_kid": body.old_kid, "rotated": True}


@router.post("/keys/{kid}/retire")
def retire_key(kid: str, request: Request) -> dict:
    state = request.app.state.obg
    state.keys.retire_key(kid)
    return {"kid": kid, "state": "retired"}


@router.get("/keys")
def list_keys(request: Request) -> dict:
    state = request.app.state.obg
    return {"keys": [serializers.key_out(k) for k in state.keys.list_keys()]}


@router.post("/consents/expire-due")
def expire_due(request: Request) -> dict:
    state = request.app.state.obg
    count = state.consents.expire_due()
    return {"expired": count}


@router.post("/callbacks/{event_id}/deliver")
def deliver_callback(event_id: str, request: Request) -> dict:
    """按退避推进事件直到 DELIVERED / DEAD（本地可注入时钟，测试用）。"""
    state = request.app.state.obg
    event = state.callbacks.deliver_until_settled(event_id)
    return serializers.event_out(event)


@router.get("/audit")
def query_audit(request: Request, tenant_id: str = "") -> dict:
    state = request.app.state.obg
    entries = state.audit.query(tenant_id or None)
    return {"audit": [
        {"audit_id": e.audit_id, "at": e.at, "tenant_id": e.tenant_id,
         "action": e.action, "result": e.result, "reason": e.reason,
         "context": e.masked_context}
        for e in entries]}


@router.get("/health")
def health(request: Request) -> dict:
    state = request.app.state.obg
    return {"status": "ok", "tenants_seeded": ["tenant-a", "tenant-b"],
            "allowed_algs": state.settings.allowed_algs}


@router.post("/_dev/reset")
def dev_reset(request: Request, random_secret: str = "") -> dict:
    """仅用于本地测试：重置全部内存数据并重新播种。"""
    state = request.app.state.obg
    state.reset()
    return {"reset": True, "secret_hint": "demo credentials restored"}


@router.post("/_dev/advance")
def dev_advance(request: Request, seconds: float = 0.0) -> dict:
    """推进可注入时钟（用于过期/退避的本地验证）。"""
    state = request.app.state.obg
    state.clock.advance(seconds)
    return {"now": state.clock.now()}
