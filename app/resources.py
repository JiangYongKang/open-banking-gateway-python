"""本地模拟银行资源服务，替代真实第三方调用方。

* 数据全部内置，不发起任何真实网络请求；
* ``delay`` 用于模拟上游耗时，配合超时上限验证资源不泄漏/不残留；
* 未知资源抛出 not_found，便于测试异常链路。
"""
from __future__ import annotations

import time

from .errors import NotFoundError

_MOCK_ACCOUNTS = {
    "acct-1": {"account_id": "acct-1", "currency": "CNY", "balance": "1000.00",
               "owner_ref": "user-001"},
    "acct-2": {"account_id": "acct-2", "currency": "USD", "balance": "42.00",
               "owner_ref": "user-002"},
}

_MOCK_TRANSACTIONS = {
    "acct-1": [
        {"txn_id": "t-1001", "amount": "-50.00", "currency": "CNY", "memo": "转账"},
        {"txn_id": "t-1002", "amount": "200.00", "currency": "CNY", "memo": "工资"},
        {"txn_id": "t-1003", "amount": "-12.50", "currency": "CNY", "memo": "消费"},
    ],
    "acct-2": [
        {"txn_id": "t-2001", "amount": "-10.00", "currency": "USD", "memo": "fee"},
    ],
}


class UpstreamTimeoutError(Exception):
    """模拟上游超时（本地用延迟触发，测试超时上限策略）。"""


class MockBankService:
    def __init__(
        self,
        *,
        delay: float = 0.0,
        timeout: float = 2.0,
        clock=time.time,
        sleep=time.sleep,
    ) -> None:
        self._delay = delay
        self._timeout = timeout
        self._clock = clock
        self._sleep = sleep

    def _simulate_call(self) -> None:
        if self._delay > self._timeout:
            # 模拟调用超过上游超时上限：直接失败，不等待完整时长，不留挂起调用
            raise UpstreamTimeoutError(f"模拟银行调用超过 {self._timeout}s 上限")
        if self._delay:
            self._sleep(self._delay)

    def get_account(self, account_id: str) -> dict:
        if account_id not in _MOCK_ACCOUNTS:
            raise NotFoundError(f"账户 {account_id!r} 不存在")
        self._simulate_call()
        return dict(_MOCK_ACCOUNTS[account_id])

    def list_transactions(self, account_id: str, limit: int = 10) -> dict:
        if account_id not in _MOCK_TRANSACTIONS:
            raise NotFoundError(f"账户 {account_id!r} 不存在")
        if limit <= 0:
            from .errors import ValidationError

            raise ValidationError("limit 必须为正整数")
        self._simulate_call()
        items = _MOCK_TRANSACTIONS[account_id][:limit]
        return {"account_id": account_id, "transactions": items, "returned": len(items)}
