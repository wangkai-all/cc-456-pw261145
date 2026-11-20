"""场景验证：重放去重、乱序暂存与释放、双密钥轮换、部分处理失败与重试。"""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from webhook_service.app import create_app
from webhook_service.crypto import make_header

SECRET = "whsec_test_initial"
KID = "k_initial"


@pytest.fixture()
def client(tmp_path):
    app = create_app(
        db_path=str(tmp_path / "test.db"),
        initial_secret=SECRET,
        tolerance_seconds=300,
        rotation_grace_seconds=3600,
    )
    with TestClient(app) as c:
        yield c


def post_event(client, seq, secret=SECRET, kid=KID, t=None, header=None,
               event_id=None, version=1, etype="ledger.credit", **payload):
    body = json.dumps({
        "event_id": event_id or f"evt_seq{seq}_v{version}",
        "version": version,
        "seq": seq,
        "type": etype,
        "payload": payload,
    }).encode()
    sig = header or make_header(secret, kid, body, t)
    return client.post("/webhook", content=body,
                       headers={"X-Webhook-Signature": sig})


def state(client):
    return client.get("/api/state").json()


# ---------- 正常按序 ----------

def test_in_order_events_applied_and_watermark_advances(client):
    for seq in (1, 2, 3):
        r = post_event(client, seq, account="alice", amount=10 * seq)
        assert r.status_code == 200 and r.json()["outcome"] == "applied"
    s = state(client)
    assert s["watermark"] == 3
    assert s["counts"]["applied"] == 3
    proj = {p["account"]: p["balance"] for p in s["projection"]}
    assert proj["alice"] == 60
    # 投影日志严格按 seq 顺序
    assert [row["seq"] for row in reversed(s["projection_log"])] == [1, 2, 3]


# ---------- 重放 / 去重 ----------

def test_duplicate_replay_is_deduplicated(client):
    body = json.dumps({
        "event_id": "evt_replay", "version": 1, "seq": 1,
        "type": "ledger.credit", "payload": {"account": "bob", "amount": 50},
    }).encode()
    header = make_header(SECRET, KID, body)
    r1 = client.post("/webhook", content=body, headers={"X-Webhook-Signature": header})
    r2 = client.post("/webhook", content=body, headers={"X-Webhook-Signature": header})
    assert r1.json()["outcome"] == "applied"
    assert r2.status_code == 200 and r2.json()["outcome"] == "duplicate"
    s = state(client)
    assert s["counts"]["applied"] == 1
    assert s["counts"]["duplicate"] == 1
    proj = {p["account"]: p["balance"] for p in s["projection"]}
    assert proj["bob"] == 50  # 只入账一次


def test_stale_version_rejected(client):
    post_event(client, 1, event_id="evt_ver", version=2, account="u", amount=1)
    r = post_event(client, 2, event_id="evt_ver", version=1, account="u", amount=1)
    assert r.status_code == 409 and r.json()["outcome"] == "stale_version"


def test_bad_signature_rejected_and_logged(client):
    r = post_event(client, 1, secret="whsec_forged", account="x", amount=1)
    assert r.status_code == 401 and r.json()["outcome"] == "rejected_bad_signature"
    s = state(client)
    assert s["watermark"] == 0
    rejected = [d for d in s["deliveries"] if d["outcome"] == "rejected_bad_signature"]
    assert len(rejected) == 1


def test_replay_with_expired_timestamp_rejected(client):
    old_t = int(time.time()) - 400  # 容差 300s
    r = post_event(client, 1, t=old_t, account="x", amount=1)
    assert r.status_code == 401 and r.json()["outcome"] == "rejected_timestamp"


# ---------- 乱序 / 暂存 / 释放 ----------

def test_out_of_order_staged_then_released_in_order(client):
    assert post_event(client, 1, account="c", amount=10).json()["outcome"] == "applied"
    # 跳空：3、4 进入暂存
    assert post_event(client, 3, account="c", amount=30).json()["outcome"] == "staged"
    assert post_event(client, 4, account="c", amount=40).json()["outcome"] == "staged"
    s = state(client)
    assert s["watermark"] == 1
    assert [e["seq"] for e in s["staged"]] == [4, 3]
    # 补齐缺口 → 2、3、4 依次释放
    assert post_event(client, 2, account="c", amount=20).json()["outcome"] == "applied"
    s = state(client)
    assert s["watermark"] == 4
    assert s["staged"] == []
    released_seqs = sorted(e["seq"] for e in s["released"])
    assert released_seqs == [3, 4]
    # 投影严格按序：10,20,30,40
    log = list(reversed(s["projection_log"]))
    assert [row["seq"] for row in log] == [1, 2, 3, 4]
    assert log[-1]["balance_after"] == 100


def test_delayed_event_below_watermark_rejected_stale(client):
    post_event(client, 1, account="d", amount=1)
    post_event(client, 2, account="d", amount=1)
    r = post_event(client, 1, event_id="evt_late_other", account="d", amount=999)
    # seq=1 已被占用，但水位检查先于 seq 冲突 → stale
    assert r.status_code == 409 and r.json()["outcome"] == "stale"


def test_seq_conflict_rejected(client):
    post_event(client, 1, account="e", amount=1)
    r = post_event(client, 2, event_id="evt_gap_filler", account="e", amount=1)
    assert r.json()["outcome"] == "applied"
    # 另一个事件试图占用已应用的 seq=2
    r = post_event(client, 2, event_id="evt_impostor", account="e", amount=1)
    assert r.status_code == 409 and r.json()["outcome"] == "stale"


# ---------- 密钥轮换 ----------

def test_dual_key_window_accepts_previous_key(client):
    client.post("/webhook", **{})  # noqa: 保证服务初始化
    rotation = client.post("/admin/keys/rotate").json()
    new_kid, new_secret = rotation["kid"], rotation["secret"]
    # 旧密钥（previous）窗口内可验签，且记录 key_role=previous
    r = post_event(client, 1, secret=SECRET, kid=KID, account="k", amount=1)
    assert r.status_code == 200 and r.json()["outcome"] == "applied"
    assert r.json()["key_role"] == "previous"
    # 新密钥正常
    r = post_event(client, 2, secret=new_secret, kid=new_kid, account="k", amount=2)
    assert r.json()["outcome"] == "applied"
    assert r.json()["key_role"] == "current"
    s = state(client)
    roles = {k["kid"]: k["role"] for k in s["keys"]}
    assert roles[KID] == "previous" and roles[new_kid] == "current"


def test_expired_previous_key_rejected(client):
    client.post("/admin/keys/rotate")
    client.post("/admin/keys/expire-previous")
    r = post_event(client, 1, secret=SECRET, kid=KID, account="k", amount=1)
    assert r.status_code == 401 and r.json()["outcome"] == "rejected_key_expired"


def test_unknown_key_rejected(client):
    r = post_event(client, 1, kid="k_nonexistent", account="k", amount=1)
    assert r.status_code == 401 and r.json()["outcome"] == "rejected_unknown_key"


# ---------- 部分处理失败 ----------

def test_partial_failure_holds_watermark_and_retry_releases(client):
    assert post_event(client, 1, account="g", amount=10).json()["outcome"] == "applied"
    # seq=2 第一次处理失败（瞬时）
    r = post_event(client, 2, account="g", amount=20, fail_attempts=1)
    assert r.json()["outcome"] == "failed"
    # 后续事件继续进入暂存
    assert post_event(client, 3, account="g", amount=30).json()["outcome"] == "staged"
    assert post_event(client, 4, etype="ledger.debit", account="g",
                      amount=5).json()["outcome"] == "staged"
    s = state(client)
    assert s["watermark"] == 1                     # 水位停在失败处
    assert s["counts"]["failed"] == 1
    assert [e["seq"] for e in s["staged"]] == [4, 3]
    proj = {p["account"]: p["balance"] for p in s["projection"]}
    assert proj["g"] == 10                         # 只有第一笔入账
    # 重放失败事件 → 去重，不会重复尝试
    r = post_event(client, 2, account="g", amount=20, fail_attempts=1)
    assert r.json()["outcome"] == "duplicate"
    assert state(client)["counts"]["failed"] == 1
    # 重试 → 成功，水位推进，暂存依次释放
    r = client.post("/admin/events/evt_seq2_v1/1/retry")
    assert r.json()["ok"] is True
    s = state(client)
    assert s["watermark"] == 4
    assert s["staged"] == []
    assert s["counts"]["applied"] == 4
    proj = {p["account"]: p["balance"] for p in s["projection"]}
    assert proj["g"] == 10 + 20 + 30 - 5


def test_permanent_failure_fixed_by_patch_then_retry(client):
    post_event(client, 1, account="h", amount=10)
    r = post_event(client, 2, account="h", amount=20, force_fail=True)
    assert r.json()["outcome"] == "failed"
    # 直接重试仍失败
    r = client.post("/admin/events/evt_seq2_v1/1/retry")
    assert r.json()["ok"] is False and r.json()["status"] == "failed"
    assert state(client)["watermark"] == 1
    # 修复 payload 后重试成功
    r = client.post("/admin/events/evt_seq2_v1/1/retry",
                    json={"patch": {"force_fail": False}})
    assert r.json()["ok"] is True
    assert state(client)["watermark"] == 2


def test_business_rule_failure_insufficient_funds(client):
    post_event(client, 1, account="i", amount=10)
    r = post_event(client, 2, etype="ledger.debit", account="i", amount=999)
    assert r.json()["outcome"] == "failed"
    assert "余额不足" in r.json()["detail"]
    assert state(client)["watermark"] == 1


# ---------- 重置 ----------

def test_reset_restores_clean_state(client):
    post_event(client, 1, account="z", amount=1)
    client.post("/admin/keys/rotate")
    client.post("/admin/reset")
    s = state(client)
    assert s["watermark"] == 0
    assert s["deliveries"] == []
    assert [k["kid"] for k in s["keys"]] == [KID]
    # 重置后初始密钥恢复可用
    r = post_event(client, 1, account="z", amount=1)
    assert r.json()["outcome"] == "applied"
