"""演示场景：构造签名事件并走真实 ingest 管线，供页面按钮/脚本触发。"""

from __future__ import annotations

import json
import time
import uuid

from . import crypto
from .core import WebhookService


def _event(seq: int, etype: str = "ledger.credit", **payload) -> bytes:
    body = {
        "event_id": "evt_" + uuid.uuid4().hex[:12],
        "version": 1,
        "seq": seq,
        "type": etype,
        "payload": payload,
    }
    return json.dumps(body, ensure_ascii=False).encode()


def _send(service: WebhookService, body: bytes, secret: str, kid: str,
          t: int | None = None, header: str | None = None) -> dict:
    sig = header or crypto.make_header(secret, kid, body, t)
    return service.ingest(body, sig)


def _current_key(service: WebhookService) -> dict:
    return service.store.get_key_by_role("current")


def _previous_key(service: WebhookService) -> dict | None:
    return service.store.get_key_by_role("previous")


def _next_seq(service: WebhookService) -> int:
    return service.store.get_watermark() + 1


def run_scenario(service: WebhookService, name: str) -> dict:
    """运行一个演示场景，返回每步结果。"""
    fn = _SCENARIOS.get(name)
    if fn is None:
        return {"ok": False, "detail": f"未知场景 {name!r}",
                "known": sorted(_SCENARIOS)}
    steps = fn(service)
    return {"ok": True, "scenario": name, "steps": steps}


def _ordered(service: WebhookService) -> list[dict]:
    """正常按序：5 笔入账依次到达。"""
    key = _current_key(service)
    base = _next_seq(service)
    steps = []
    for i in range(5):
        body = _event(base + i, account="alice", amount=10 * (i + 1))
        steps.append(_send(service, body, key["secret"], key["kid"]))
    return steps


def _duplicate(service: WebhookService) -> list[dict]:
    """重放：同一签名投递原样发送两次，第二次被去重。"""
    key = _current_key(service)
    body = _event(_next_seq(service), account="bob", amount=50)
    header = crypto.make_header(key["secret"], key["kid"], body)
    first = _send(service, body, key["secret"], key["kid"], header=header)
    replay = _send(service, body, key["secret"], key["kid"], header=header)
    return [first, replay]


def _out_of_order(service: WebhookService) -> list[dict]:
    """乱序：跳过一笔先发后续，后到的进入暂存区；补齐缺口后按序释放。"""
    key = _current_key(service)
    base = _next_seq(service)
    steps = []
    for seq, amount in ((base, 10), (base + 1, 20), (base + 3, 40), (base + 4, 50)):
        body = _event(seq, account="carol", amount=amount)
        steps.append(_send(service, body, key["secret"], key["kid"]))
    # 补齐缺口 seq=base+2 → 触发 base+3、base+4 依次释放
    body = _event(base + 2, account="carol", amount=30)
    steps.append(_send(service, body, key["secret"], key["kid"]))
    return steps


def _delayed_stale(service: WebhookService) -> list[dict]:
    """延迟：水位已过的迟到事件被拒绝（stale）。"""
    key = _current_key(service)
    watermark = service.store.get_watermark()
    if watermark < 1:
        # 先制造水位
        body = _event(1, account="dave", amount=5)
        _send(service, body, key["secret"], key["kid"])
        watermark = 1
    body = _event(watermark, account="dave", amount=999)  # 占用已过的序号
    return [_send(service, body, key["secret"], key["kid"])]


def _key_rotation(service: WebhookService) -> list[dict]:
    """密钥轮换：轮换后旧密钥（previous）在窗口内仍可验签，新密钥正常。"""
    rotation = service.rotate_key()
    old_kid = rotation["previous_kid"]
    old_secret = service.store.get_key(old_kid)["secret"]
    new_kid, new_secret = rotation["kid"], rotation["secret"]
    base = _next_seq(service)
    steps = [
        _send(service, _event(base, account="erin", amount=11), old_secret, old_kid),
        _send(service, _event(base + 1, account="erin", amount=22), new_secret, new_kid),
    ]
    return steps


def _expired_old_key(service: WebhookService) -> list[dict]:
    """窗口关闭：结束双密钥窗口后，旧密钥签名被拒。"""
    if not _previous_key(service):
        service.rotate_key()  # 没有窗口就先制造一个
    previous = _previous_key(service)
    old_secret = service.store.get_key(previous["kid"])["secret"]
    service.expire_previous_key()
    body = _event(_next_seq(service), account="frank", amount=7)
    return [_send(service, body, old_secret, previous["kid"])]


def _bad_signature(service: WebhookService) -> list[dict]:
    """伪造签名：错误密钥签名被拒。"""
    key = _current_key(service)
    body = _event(_next_seq(service), account="mallory", amount=1000)
    return [_send(service, body, "whsec_forged", key["kid"])]


def _replay_old_timestamp(service: WebhookService) -> list[dict]:
    """重放：签名时间戳超出容差窗口被拒。"""
    key = _current_key(service)
    body = _event(_next_seq(service), account="mallory", amount=1000)
    old_t = int(time.time()) - service.tolerance - 60
    return [_send(service, body, key["secret"], key["kid"], t=old_t)]


def _partial_failure(service: WebhookService) -> list[dict]:
    """部分失败：一批中第二笔瞬时失败一次 → 水位停住、后续暂存；
    重试成功后水位推进、暂存释放。"""
    key = _current_key(service)
    base = _next_seq(service)
    specs = [
        (base, "ledger.credit", {"account": "grace", "amount": 10}),
        (base + 1, "ledger.credit",
         {"account": "grace", "amount": 20, "fail_attempts": 1}),
        (base + 2, "ledger.credit", {"account": "grace", "amount": 30}),
        (base + 3, "ledger.debit", {"account": "grace", "amount": 5}),
    ]
    steps = []
    for seq, etype, payload in specs:
        body = _event(seq, etype, **payload)
        steps.append(_send(service, body, key["secret"], key["kid"]))
    return steps


_SCENARIOS = {
    "ordered": _ordered,
    "duplicate": _duplicate,
    "out_of_order": _out_of_order,
    "delayed_stale": _delayed_stale,
    "key_rotation": _key_rotation,
    "expired_old_key": _expired_old_key,
    "bad_signature": _bad_signature,
    "replay_old_timestamp": _replay_old_timestamp,
    "partial_failure": _partial_failure,
}
