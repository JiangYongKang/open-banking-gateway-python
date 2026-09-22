"""领域对象到 API 响应的序列化。"""
from __future__ import annotations

from dataclasses import asdict

from app.models import CallbackEvent, Consent, PartnerCredential, SigningKey


def key_out(k: SigningKey) -> dict:
    return {
        "kid": k.kid, "alg": k.alg, "state": k.state.value,
        "created_at": k.created_at, "retired_at": k.retired_at,
    }


def credential_out(c: PartnerCredential) -> dict:
    return {
        "credential_id": c.credential_id, "tenant_id": c.tenant_id,
        "scopes": list(c.scopes), "revoked": c.revoked,
        "expires_at": c.expires_at,
    }


def consent_out(c: Consent) -> dict:
    return {
        "consent_id": c.consent_id, "tenant_id": c.tenant_id,
        "scopes": list(c.scopes), "account_ids": list(c.account_ids),
        "status": c.status.value, "created_at": c.created_at,
        "expires_at": c.expires_at, "authorized_at": c.authorized_at,
        "revoked_at": c.revoked_at, "revoke_reason": c.revoke_reason,
        "history": [asdict(h) for h in c.history],
    }


def event_out(e: CallbackEvent) -> dict:
    return {
        "event_id": e.event_id, "tenant_id": e.tenant_id,
        "callback_url": e.callback_url, "status": e.status.value,
        "attempts": e.attempts, "max_attempts": e.max_attempts,
        "created_at": e.created_at, "next_attempt_at": e.next_attempt_at,
        "delivered_at": e.delivered_at, "last_error": e.last_error,
        "attempt_history": list(e.attempt_history),
    }
