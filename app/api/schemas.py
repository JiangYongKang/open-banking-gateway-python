"""请求/响应 Pydantic 模型。"""
from __future__ import annotations

from pydantic import BaseModel, Field


class TokenRequest(BaseModel):
    credential_id: str
    secret: str


class ConsentCreateRequest(BaseModel):
    scopes: list[str] = Field(min_length=1)
    account_ids: list[str] = Field(default_factory=list)
    ttl_seconds: int = Field(default=600, gt=0)


class RevokeRequest(BaseModel):
    reason: str = ""


class CallbackTriggerRequest(BaseModel):
    event_id: str = Field(min_length=1)
    callback_url: str = Field(min_length=1)
    payload: dict = Field(default_factory=dict)


class CredentialRegisterRequest(BaseModel):
    credential_id: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)
    secret: str = Field(min_length=1)
    scopes: list[str] = Field(default_factory=list)
    ttl_seconds: int = 0


class KeyAddRequest(BaseModel):
    kid: str = Field(min_length=1)
    alg: str = "HS256"
    secret: str = Field(min_length=1)


class KeyRotateRequest(BaseModel):
    new_kid: str = Field(min_length=1)
    old_kid: str = Field(min_length=1)
    alg: str = "HS256"
    new_secret: str = Field(min_length=1)
