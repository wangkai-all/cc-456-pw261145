"""核心接收管线。

每条投递的处理顺序（ingest）：
1. 解析签名头 → 2. 选钥（current，或窗口期内的 previous）→ 3. 验签 →
4. 时间戳容差（防重放）→ 5. 解析事件体 → 6. 临界区内：
   按 (event_id, version) 去重 → 版本/水位过期检查 → seq 冲突检查 →
   落库（staged）→ 若 seq == 水位+1 则沿连续序列应用并推进水位（_drain），
   处理器失败则该事件置 failed、水位停住、后续事件继续留在暂存区。
"""

from __future__ import annotations

import json
import threading
import time
import uuid

from . import crypto, handlers
from .store import Store

# 投递结果
APPLIED = "applied"
STAGED = "staged"
DUPLICATE = "duplicate"
FAILED = "failed"
STALE = "stale"
STALE_VERSION = "stale_version"
REJ_BAD_SIG = "rejected_bad_signature"
REJ_TIMESTAMP = "rejected_timestamp"
REJ_UNKNOWN_KEY = "rejected_unknown_key"
REJ_KEY_EXPIRED = "rejected_key_expired"
REJ_SEQ_CONFLICT = "rejected_seq_conflict"
REJ_INVALID = "rejected_invalid_payload"

_HTTP = {
    APPLIED: 200, STAGED: 202, DUPLICATE: 200, FAILED: 200,
    STALE: 409, STALE_VERSION: 409, REJ_SEQ_CONFLICT: 409,
    REJ_BAD_SIG: 401, REJ_UNKNOWN_KEY: 401, REJ_KEY_EXPIRED: 401,
    REJ_TIMESTAMP: 401, REJ_INVALID: 400,
}


class WebhookService:
    def __init__(
        self,
        store: Store,
        tolerance_seconds: int = 300,
        rotation_grace_seconds: int = 3600,
        initial_secret: str = "whsec_dev_initial",
    ):
        self.store = store
        self.tolerance = tolerance_seconds
        self.grace = rotation_grace_seconds
        self.initial_secret = initial_secret
        self._lock = threading.RLock()
        with self._lock:
            if not self.store.get_key_by_role("current"):
                self.store.insert_key("k_initial", initial_secret, "current")

    # ================= 接收管线 =================

    def ingest(self, raw_body: bytes, signature_header: str | None,
               delivery_id: str | None = None) -> dict:
        now = time.time()
        rec: dict = {"delivery_id": delivery_id, "received_at": now}

        # 1. 解析签名头
        parsed = crypto.parse_header(signature_header)
        if parsed is None:
            return self._finish(rec, REJ_BAD_SIG, "签名头缺失或格式非法")

        # 2. 选钥：优先头里的 kid；缺省时依次尝试 current、窗口内 previous
        key, key_role, key_err = self._select_key(parsed["kid"], now)
        if key is None:
            return self._finish(rec, key_err, f"kid={parsed['kid']!r} 不可用", kid=parsed["kid"])

        # 3. 验签
        if not crypto.verify(key["secret"], raw_body, parsed["t"], parsed["sig"]):
            return self._finish(rec, REJ_BAD_SIG, "HMAC 校验失败",
                                key_role=key_role, kid=key["kid"])

        # 4. 时间戳容差（防重放）
        skew = abs(now - parsed["t"])
        if skew > self.tolerance:
            return self._finish(rec, REJ_TIMESTAMP,
                                f"时间戳偏差 {skew:.0f}s 超过容差 {self.tolerance}s",
                                key_role=key_role, kid=key["kid"])

        # 5. 解析事件体
        try:
            event = self._parse_event(raw_body)
        except ValueError as exc:
            return self._finish(rec, REJ_INVALID, str(exc),
                                key_role=key_role, kid=key["kid"])
        rec.update(event_id=event["event_id"], version=event["version"], seq=event["seq"])

        # 6. 临界区：去重 + 定序 + 应用
        with self._lock:
            outcome, detail = self._ingest_locked(event, key_role, now)
        return self._finish(rec, outcome, detail, key_role=key_role, kid=key["kid"])

    def _select_key(self, kid: str | None, now: float):
        """返回 (key, key_role, error_outcome)。key 为 None 时 error_outcome 有效。"""
        candidates: list[tuple[dict, str]] = []
        current = self.store.get_key_by_role("current")
        if current:
            candidates.append((current, "current"))
        previous = self.store.get_key_by_role("previous")
        if previous and self._previous_in_window(previous, now):
            candidates.append((previous, "previous"))

        if kid is None:
            if candidates:
                key, role = candidates[0]
                return key, role, None
            return None, None, REJ_UNKNOWN_KEY
        for key, role in candidates:
            if key["kid"] == kid:
                return key, role, None
        # kid 存在但已退役/窗口关闭 → 区分“从未见过”与“窗口已关闭”
        known = self.store.get_key(kid)
        if known is not None:
            return None, None, REJ_KEY_EXPIRED
        return None, None, REJ_UNKNOWN_KEY

    def _previous_in_window(self, previous: dict, now: float) -> bool:
        rotated_at = previous.get("rotated_at")
        return rotated_at is not None and (now - rotated_at) <= self.grace

    @staticmethod
    def _parse_event(raw_body: bytes) -> dict:
        try:
            data = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            raise ValueError(f"事件体不是合法 JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("事件体必须是 JSON 对象")
        event_id = data.get("event_id")
        version = data.get("version")
        seq = data.get("seq")
        etype = data.get("type")
        payload = data.get("payload", {})
        if not event_id or not isinstance(event_id, str):
            raise ValueError("缺少合法 event_id")
        if not isinstance(version, int) or version < 1:
            raise ValueError("version 必须为 >=1 的整数")
        if not isinstance(seq, int) or seq < 1:
            raise ValueError("seq 必须为 >=1 的整数")
        if not etype or not isinstance(etype, str):
            raise ValueError("缺少合法 type")
        if not isinstance(payload, dict):
            raise ValueError("payload 必须为对象")
        return {"event_id": event_id, "version": version, "seq": seq,
                "type": etype, "payload": payload}

    def _ingest_locked(self, event: dict, key_role: str, now: float):
        """返回 (outcome, detail)。调用方持有 self._lock。"""
        store = self.store
        eid, ver, seq = event["event_id"], event["version"], event["seq"]

        # 去重：同一 (event_id, version) 重复投递 → 幂等返回已有状态
        existing = store.get_event(eid, ver)
        if existing is not None:
            return DUPLICATE, f"事件已存在（状态 {existing['status']}），本次投递被去重"

        # 旧版本：同一 event_id 已有更高版本
        max_ver = store.max_version_for(eid)
        if max_ver is not None and ver < max_ver:
            return STALE_VERSION, f"事件 {eid} 已存在版本 {max_ver}，版本 {ver} 过期"

        # 水位已过：该 seq 位置早已被应用
        watermark = store.get_watermark()
        if seq <= watermark:
            return STALE, f"水位已推进到 {watermark}，seq={seq} 的迟到事件被拒绝"

        # seq 冲突：同一序号被不同事件占用
        at_seq = store.get_event_by_seq(seq)
        if at_seq is not None:
            return REJ_SEQ_CONFLICT, (
                f"seq={seq} 已被事件 {at_seq['event_id']} 占用，"
                f"与 {eid} 冲突")

        # 落库；仅当需要真正等待（seq 超过水位+1）时才标记 staged_at，
        # 使“释放记录”只包含确实在暂存区等待过的事件
        will_wait = seq > watermark + 1
        store.insert_event({**event, "status": "staged", "key_role": key_role,
                            "first_received_at": now,
                            "staged_at": now if will_wait else None})
        if not will_wait:
            self._drain_locked()
            final = store.get_event(eid, ver)
            if final["status"] == "applied":
                return APPLIED, "按序应用，水位推进"
            return FAILED, f"处理失败：{final['fail_reason']}（水位停在 {watermark}）"
        return STAGED, f"乱序到达：等待 seq={watermark + 1}，进入暂存区"

    def _drain_locked(self) -> None:
        """从水位+1 起沿连续 seq 应用事件，推进水位；遇失败即停。"""
        store = self.store
        while True:
            watermark = store.get_watermark()
            nxt = store.get_event_by_seq(watermark + 1)
            if nxt is None or nxt["status"] != "staged":
                return
            # bump 返回的是“本次为第几次尝试”，处理器需要此前的失败次数
            nxt["attempts"] = store.bump_attempts(nxt["event_id"], nxt["version"]) - 1
            try:
                handlers.apply_event(nxt, store)
            except handlers.HandlerError as exc:
                store.mark_failed(nxt["event_id"], nxt["version"], str(exc))
                return
            store.mark_applied(nxt["event_id"], nxt["version"], time.time())
            store.set_watermark(watermark + 1)

    def _finish(self, rec: dict, outcome: str, detail: str,
                key_role: str | None = None, kid: str | None = None) -> dict:
        rec.update(outcome=outcome, detail=detail, key_role=key_role, kid=kid)
        self.store.log_delivery(rec)
        return {"outcome": outcome, "detail": detail, "key_role": key_role,
                "event_id": rec.get("event_id"), "version": rec.get("version"),
                "seq": rec.get("seq"), "http_status": _HTTP[outcome]}

    # ================= 失败重试 =================

    def retry_event(self, event_id: str, version: int,
                    patch: dict | None = None) -> dict:
        """重试 failed 事件；patch 可先修复 payload（如去掉 force_fail）。"""
        with self._lock:
            ev = self.store.get_event(event_id, version)
            if ev is None:
                return {"ok": False, "detail": "事件不存在"}
            if ev["status"] != "failed":
                return {"ok": False, "detail": f"事件状态为 {ev['status']}，仅 failed 可重试"}
            if patch:
                ev["payload"].update(patch)
                self.store.update_payload(event_id, version, ev["payload"])
            self.store.mark_staged(event_id, version)
            watermark = self.store.get_watermark()
            if ev["seq"] == watermark + 1:
                self._drain_locked()
            final = self.store.get_event(event_id, version)
            return {"ok": final["status"] == "applied", "status": final["status"],
                    "fail_reason": final["fail_reason"],
                    "watermark": self.store.get_watermark()}

    # ================= 密钥轮换 =================

    def rotate_key(self) -> dict:
        """轮换：current→previous（进入宽限窗口），旧 previous→retired，生成新 current。"""
        with self._lock:
            now = time.time()
            old_previous = self.store.get_key_by_role("previous")
            if old_previous:
                self.store.set_key_role(old_previous["kid"], "retired", now)
            current = self.store.get_key_by_role("current")
            if current:
                self.store.set_key_role(current["kid"], "previous", now)
            kid = "k_" + uuid.uuid4().hex[:8]
            secret = "whsec_" + uuid.uuid4().hex
            self.store.insert_key(kid, secret, "current")
            return {"kid": kid, "secret": secret,
                    "previous_kid": current["kid"] if current else None,
                    "grace_seconds": self.grace}

    def expire_previous_key(self) -> dict:
        """立即结束双密钥窗口（previous→retired），此后旧密钥签名被拒。"""
        with self._lock:
            previous = self.store.get_key_by_role("previous")
            if not previous:
                return {"ok": False, "detail": "当前没有 previous 密钥"}
            self.store.set_key_role(previous["kid"], "retired", time.time())
            return {"ok": True, "retired_kid": previous["kid"]}

    # ================= 状态查询 =================

    def state(self) -> dict:
        now = time.time()
        keys = []
        for k in self.store.list_keys():
            item = dict(k)
            if k["role"] == "previous" and k.get("rotated_at"):
                remaining = self.grace - (now - k["rotated_at"])
                item["grace_remaining"] = max(0, round(remaining))
                item["in_window"] = remaining > 0
            keys.append(item)
        watermark = self.store.get_watermark()
        staged = self.store.list_events(status="staged")
        for ev in staged:
            ev["waiting_for"] = watermark + 1
        return {
            "watermark": watermark,
            "keys": keys,
            "counts": self.store.event_counts(),
            "deliveries": self.store.list_deliveries(),
            "staged": staged,
            "released": self.store.list_released(),
            "failed": self.store.list_events(status="failed"),
            "projection": self.store.list_projection(),
            "projection_log": self.store.list_projection_log(),
            "config": {"tolerance_seconds": self.tolerance,
                       "rotation_grace_seconds": self.grace},
        }

    def reset(self) -> None:
        with self._lock:
            self.store.reset()
            self.store.insert_key("k_initial", self.initial_secret, "current")
