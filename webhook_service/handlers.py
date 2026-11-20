"""业务处理器：把事件应用到账本投影，演示“部分处理失败”。

失败语义：
- 瞬时失败：payload.fail_attempts = n → 前 n 次处理尝试抛错，之后成功（重试可恢复）。
- 永久失败：payload.force_fail = true、金额非法、余额不足 → 除非修复 payload
  （POST /admin/events/{id}/{ver}/retry 支持 patch），否则一直失败。
"""


class HandlerError(Exception):
    """处理器业务失败。transient=True 表示重试可能成功。"""

    def __init__(self, message: str, transient: bool = False):
        super().__init__(message)
        self.transient = transient


def apply_event(event: dict, store) -> None:
    """把单条事件应用到投影。抛 HandlerError 表示处理失败。"""
    payload = event["payload"]
    attempts_before = event["attempts"]  # 本次尝试之前已失败/尝试的次数

    fail_attempts = int(payload.get("fail_attempts", 0) or 0)
    if attempts_before < fail_attempts:
        raise HandlerError(
            f"模拟瞬时故障（第 {attempts_before + 1}/{fail_attempts} 次尝试）",
            transient=True,
        )
    if payload.get("force_fail"):
        raise HandlerError("payload 标记 force_fail，处理被强制失败")

    etype = event["type"]
    if etype not in ("ledger.credit", "ledger.debit"):
        raise HandlerError(f"未知事件类型: {etype}")

    account = payload.get("account")
    amount = payload.get("amount")
    if not account or not isinstance(account, str):
        raise HandlerError("payload 缺少合法 account 字段")
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        raise HandlerError(f"amount 必须为正整数，实际: {amount!r}")

    if etype == "ledger.debit":
        balance = store.get_balance(account)
        if amount > balance:
            raise HandlerError(f"余额不足：账户 {account} 余额 {balance}，需扣减 {amount}")
        delta = -amount
    else:
        delta = amount

    store.apply_projection(account, delta, event["seq"], event["event_id"])
