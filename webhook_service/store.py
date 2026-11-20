"""SQLite 持久化层：密钥、水位、事件、投递日志、业务投影。

单连接 + 可重入锁串行化所有访问（演示规模足够，语义上保证
“检查-写入”临界区原子）。WAL 模式允许读写并发。
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS keys (
    kid        TEXT PRIMARY KEY,
    secret     TEXT NOT NULL,
    role       TEXT NOT NULL,            -- current | previous | retired
    created_at REAL NOT NULL,
    rotated_at REAL                      -- 被降级为 previous 的时刻（窗口起点）
);

CREATE TABLE IF NOT EXISTS watermark (
    id  INTEGER PRIMARY KEY CHECK (id = 1),
    seq INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    event_id          TEXT NOT NULL,
    version           INTEGER NOT NULL,
    seq               INTEGER NOT NULL,
    type              TEXT NOT NULL,
    payload           TEXT NOT NULL,     -- JSON 字符串
    status            TEXT NOT NULL,     -- staged | applied | failed
    key_role          TEXT,              -- 验签所用密钥角色 current | previous
    attempts          INTEGER NOT NULL DEFAULT 0,
    fail_reason       TEXT,
    first_received_at REAL NOT NULL,
    staged_at         REAL,
    applied_at        REAL,
    PRIMARY KEY (event_id, version)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_seq ON events(seq);

CREATE TABLE IF NOT EXISTS deliveries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_id TEXT,
    event_id    TEXT,
    version     INTEGER,
    seq         INTEGER,
    outcome     TEXT NOT NULL,           -- applied|staged|duplicate|failed|stale|stale_version|rejected_*
    key_role    TEXT,
    kid         TEXT,
    detail      TEXT,
    received_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS projection (
    account    TEXT PRIMARY KEY,
    balance    INTEGER NOT NULL,
    last_seq   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS projection_log (
    seq           INTEGER PRIMARY KEY,
    event_id      TEXT NOT NULL,
    account       TEXT NOT NULL,
    delta         INTEGER NOT NULL,
    balance_after INTEGER NOT NULL,
    applied_at    REAL NOT NULL
);
"""


class Store:
    def __init__(self, path: str = "webhook.db"):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)
        self._lock = threading.RLock()
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO watermark(id, seq) VALUES (1, 0)"
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---------- 密钥 ----------

    def insert_key(self, kid: str, secret: str, role: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO keys(kid, secret, role, created_at) VALUES (?,?,?,?)",
                (kid, secret, role, time.time()),
            )

    def get_key(self, kid: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM keys WHERE kid=?", (kid,)
            ).fetchone()
            return dict(row) if row else None

    def get_key_by_role(self, role: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM keys WHERE role=? ORDER BY created_at DESC LIMIT 1",
                (role,),
            ).fetchone()
            return dict(row) if row else None

    def list_keys(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT kid, role, created_at, rotated_at FROM keys ORDER BY created_at"
            ).fetchall()
            return [dict(r) for r in rows]

    def set_key_role(self, kid: str, role: str, rotated_at: float | None = None) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE keys SET role=?, rotated_at=? WHERE kid=?",
                (role, rotated_at, kid),
            )

    # ---------- 水位 ----------

    def get_watermark(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT seq FROM watermark WHERE id=1").fetchone()
            return int(row["seq"])

    def set_watermark(self, seq: int) -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE watermark SET seq=? WHERE id=1", (seq,))

    # ---------- 事件 ----------

    def insert_event(self, ev: dict) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO events(event_id, version, seq, type, payload, status,
                                      key_role, first_received_at, staged_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    ev["event_id"], ev["version"], ev["seq"], ev["type"],
                    json.dumps(ev["payload"], ensure_ascii=False), ev["status"],
                    ev.get("key_role"), ev["first_received_at"], ev.get("staged_at"),
                ),
            )

    def get_event(self, event_id: str, version: int) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM events WHERE event_id=? AND version=?",
                (event_id, version),
            ).fetchone()
            return self._event_row(row) if row else None

    def get_event_by_seq(self, seq: int) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM events WHERE seq=?", (seq,)
            ).fetchone()
            return self._event_row(row) if row else None

    def max_version_for(self, event_id: str) -> int | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(version) AS v FROM events WHERE event_id=?", (event_id,)
            ).fetchone()
            return row["v"] if row and row["v"] is not None else None

    def bump_attempts(self, event_id: str, version: int) -> int:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE events SET attempts=attempts+1 WHERE event_id=? AND version=?",
                (event_id, version),
            )
            return self.get_event(event_id, version)["attempts"]

    def mark_applied(self, event_id: str, version: int, applied_at: float) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """UPDATE events SET status='applied', applied_at=?, fail_reason=NULL
                   WHERE event_id=? AND version=?""",
                (applied_at, event_id, version),
            )

    def mark_failed(self, event_id: str, version: int, reason: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE events SET status='failed', fail_reason=? WHERE event_id=? AND version=?",
                (reason, event_id, version),
            )

    def mark_staged(self, event_id: str, version: int) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE events SET status='staged', fail_reason=NULL WHERE event_id=? AND version=?",
                (event_id, version),
            )

    def update_payload(self, event_id: str, version: int, payload: dict) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE events SET payload=? WHERE event_id=? AND version=?",
                (json.dumps(payload, ensure_ascii=False), event_id, version),
            )

    def list_events(self, status: str | None = None, limit: int = 200) -> list[dict]:
        with self._lock:
            if status:
                rows = self._conn.execute(
                    "SELECT * FROM events WHERE status=? ORDER BY seq DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM events ORDER BY seq DESC LIMIT ?", (limit,)
                ).fetchall()
            return [self._event_row(r) for r in rows]

    def list_released(self, limit: int = 200) -> list[dict]:
        """曾被暂存、随后随水位推进而释放应用的事件。"""
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM events
                   WHERE status='applied' AND staged_at IS NOT NULL
                   ORDER BY applied_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            return [self._event_row(r) for r in rows]

    def event_counts(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) AS n FROM events GROUP BY status"
            ).fetchall()
            counts = {r["status"]: r["n"] for r in rows}
            dup = self._conn.execute(
                "SELECT COUNT(*) AS n FROM deliveries WHERE outcome='duplicate'"
            ).fetchone()["n"]
            rej = self._conn.execute(
                """SELECT COUNT(*) AS n FROM deliveries
                   WHERE outcome LIKE 'rejected%' OR outcome IN ('stale','stale_version')"""
            ).fetchone()["n"]
            counts["duplicate"] = dup
            counts["rejected"] = rej
            return counts

    @staticmethod
    def _event_row(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["payload"] = json.loads(d["payload"])
        return d

    # ---------- 投递日志 ----------

    def log_delivery(self, rec: dict) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO deliveries(delivery_id, event_id, version, seq, outcome,
                                          key_role, kid, detail, received_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    rec.get("delivery_id"), rec.get("event_id"), rec.get("version"),
                    rec.get("seq"), rec["outcome"], rec.get("key_role"),
                    rec.get("kid"), rec.get("detail"), rec["received_at"],
                ),
            )

    def list_deliveries(self, limit: int = 300) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM deliveries ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ---------- 业务投影 ----------

    def apply_projection(self, account: str, delta: int, seq: int, event_id: str) -> int:
        """应用账本变更，返回新余额。调用方须已持有核心锁。"""
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT balance FROM projection WHERE account=?", (account,)
            ).fetchone()
            balance = (row["balance"] if row else 0) + delta
            self._conn.execute(
                """INSERT INTO projection(account, balance, last_seq) VALUES (?,?,?)
                   ON CONFLICT(account) DO UPDATE SET balance=excluded.balance,
                                                      last_seq=excluded.last_seq""",
                (account, balance, seq),
            )
            self._conn.execute(
                """INSERT INTO projection_log(seq, event_id, account, delta,
                                              balance_after, applied_at)
                   VALUES (?,?,?,?,?,?)""",
                (seq, event_id, account, delta, balance, time.time()),
            )
            return balance

    def get_balance(self, account: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT balance FROM projection WHERE account=?", (account,)
            ).fetchone()
            return row["balance"] if row else 0

    def list_projection(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM projection ORDER BY account"
            ).fetchall()
            return [dict(r) for r in rows]

    def list_projection_log(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM projection_log ORDER BY seq DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ---------- 重置 ----------

    def reset(self) -> None:
        with self._lock, self._conn:
            for table in ("events", "deliveries", "projection", "projection_log", "keys"):
                self._conn.execute(f"DELETE FROM {table}")
            self._conn.execute("UPDATE watermark SET seq=0 WHERE id=1")
