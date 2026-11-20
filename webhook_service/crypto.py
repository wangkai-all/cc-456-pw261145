"""HMAC-SHA256 签名工具（Stripe 风格头：t=<ts>,kid=<key_id>,v1=<hex>）。"""

from __future__ import annotations

import hashlib
import hmac
import time


def sign_payload(secret: str, body: bytes, t: int | None = None) -> str:
    """对 ``f"{t}.{body}"`` 计算 HMAC-SHA256，返回十六进制摘要。"""
    ts = int(time.time()) if t is None else int(t)
    msg = str(ts).encode() + b"." + body
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def make_header(secret: str, kid: str, body: bytes, t: int | None = None) -> str:
    ts = int(time.time()) if t is None else int(t)
    return f"t={ts},kid={kid},v1={sign_payload(secret, body, ts)}"


def parse_header(header: str | None) -> dict | None:
    """解析签名头，返回 {t, kid, sig}；格式非法返回 None。"""
    if not header:
        return None
    parts: dict[str, str] = {}
    for piece in header.split(","):
        if "=" not in piece:
            return None
        k, v = piece.split("=", 1)
        parts[k.strip()] = v.strip()
    if "t" not in parts or "v1" not in parts:
        return None
    try:
        t = int(parts["t"])
    except ValueError:
        return None
    return {"t": t, "kid": parts.get("kid") or None, "sig": parts["v1"]}


def verify(secret: str, body: bytes, t: int, sig: str) -> bool:
    return hmac.compare_digest(sign_payload(secret, body, t), sig)
