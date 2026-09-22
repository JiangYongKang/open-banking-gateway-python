"""本地存储：线程安全内存表 + 可选 JSON 原子落盘。

历史型集合（consents / events / audit）由各服务以“整体替换状态、只追加历史”
的方式更新，本模块只负责容器与序列化，不做业务判断。
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import asdict

from app.models import (
    CallbackEvent,
    CallbackStatus,
    Consent,
    ConsentHistoryEntry,
    ConsentStatus,
    KeyState,
    PartnerCredential,
    SigningKey,
    WindowCounter,
)


def _consent_from_dict(d: dict) -> Consent:
    d = dict(d)
    d["status"] = ConsentStatus(d["status"])
    d["history"] = [ConsentHistoryEntry(**h) for h in d.get("history", [])]
    return Consent(**d)


def _event_from_dict(d: dict) -> CallbackEvent:
    d = dict(d)
    d["status"] = CallbackStatus(d["status"])
    return CallbackEvent(**d)


class Storage:
    """所有读写均应在 self.lock 保护下进行（服务层持锁调用）。"""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.keys: dict[str, SigningKey] = {}
        self.credentials: dict[str, PartnerCredential] = {}
        self.consents: dict[str, Consent] = {}
        self.events: dict[str, CallbackEvent] = {}
        # 限流计数: (tenant_id, endpoint) -> WindowCounter
        self.rate_counters: dict[tuple[str, str], WindowCounter] = {}
        # 日配额计数: (tenant_id, date) -> int
        self.quota_counters: dict[tuple[str, str], int] = {}

    # ---- 序列化 -------------------------------------------------------
    def to_dict(self) -> dict:
        with self.lock:
            return {
                "keys": [asdict(k) for k in self.keys.values()],
                "credentials": [asdict(c) for c in self.credentials.values()],
                "consents": [asdict(c) for c in self.consents.values()],
                "events": [asdict(e) for e in self.events.values()],
                "rate_counters": [[list(k), asdict(v)]
                                  for k, v in self.rate_counters.items()],
                "quota_counters": [[list(k), v] for k, v in self.quota_counters.items()],
            }

    def load_dict(self, data: dict) -> None:
        with self.lock:
            self.reset()
            for d in data.get("keys", []):
                key = SigningKey(**{**d, "state": KeyState(d["state"])})
                self.keys[key.kid] = key
            for d in data.get("credentials", []):
                cred = PartnerCredential(**d)
                self.credentials[cred.credential_id] = cred
            for d in data.get("consents", []):
                consent = _consent_from_dict(d)
                self.consents[consent.consent_id] = consent
            for d in data.get("events", []):
                event = _event_from_dict(d)
                self.events[event.event_id] = event
            for key, v in data.get("rate_counters", []):
                self.rate_counters[(key[0], key[1])] = WindowCounter(**v)
            for key, v in data.get("quota_counters", []):
                self.quota_counters[(key[0], key[1])] = v

    def save(self, path: str) -> None:
        """原子写入：先写临时文件再 rename，避免半文件。"""
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        payload = json.dumps(self.to_dict(), ensure_ascii=False, indent=2)
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def load(self, path: str) -> None:
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as fh:
            self.load_dict(json.load(fh))

    def reset(self) -> None:
        """清空全部数据（测试用）。"""
        with self.lock:
            self.keys.clear()
            self.credentials.clear()
            self.consents.clear()
            self.events.clear()
            self.rate_counters.clear()
            self.quota_counters.clear()
