"""Guardian database — SQLite setup, migrations, cursor management."""

import os
import json
import sqlite3
import logging
import threading
from contextlib import contextmanager
from typing import Optional

from guardian_engine.errors import StorageError, CorruptionError

logger = logging.getLogger("guardian.db")

DEFAULT_DB_PATH = "./guardian.db"

SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS policies (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        content TEXT NOT NULL,
        hash TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        created_by TEXT,
        created_at TEXT NOT NULL,
        UNIQUE(name, version)
    );

    CREATE TABLE IF NOT EXISTS rules (
        id TEXT PRIMARY KEY,
        policy_id TEXT NOT NULL,
        priority INTEGER NOT NULL,
        effect TEXT NOT NULL,
        match_def TEXT NOT NULL,
        where_def TEXT,
        config TEXT,
        reason TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL,
        FOREIGN KEY (policy_id) REFERENCES policies(id)
    );
    CREATE INDEX IF NOT EXISTS idx_rules_policy ON rules(policy_id);
    CREATE INDEX IF NOT EXISTS idx_rules_priority ON rules(priority DESC);

    CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'info',
        outcome TEXT NOT NULL,
        actor_type TEXT,
        actor_id TEXT,
        session_id TEXT,
        channel_id TEXT,
        tool TEXT,
        action TEXT,
        resource_type TEXT,
        resource_id TEXT,
        rule_id TEXT,
        policy_id TEXT,
        decision TEXT,
        reason TEXT,
        details TEXT,
        correlation_id TEXT,
        latency_us INTEGER,
        event_hash TEXT NOT NULL,
        prev_event_hash TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_log(event_type, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_log(correlation_id);

    CREATE TABLE IF NOT EXISTS metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        metric_name TEXT NOT NULL,
        value REAL NOT NULL,
        dimensions TEXT,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_metrics_name_time ON metrics(metric_name, timestamp DESC);

    CREATE TABLE IF NOT EXISTS metrics_rollup (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        period_start TEXT NOT NULL,
        period_end TEXT NOT NULL,
        metric_name TEXT NOT NULL,
        dimensions TEXT,
        count INTEGER NOT NULL,
        sum_val REAL NOT NULL,
        min_val REAL NOT NULL,
        max_val REAL NOT NULL,
        avg_val REAL NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_rollup_name ON metrics_rollup(metric_name, period_start DESC);

    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        metric_name TEXT NOT NULL,
        metric_value REAL,
        threshold REAL,
        message TEXT NOT NULL,
        fired_at TEXT NOT NULL,
        acknowledged INTEGER DEFAULT 0,
        acknowledged_by TEXT,
        acknowledged_at TEXT,
        resolved INTEGER DEFAULT 0,
        resolved_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_alerts_active ON alerts(resolved, fired_at DESC);

    CREATE TABLE IF NOT EXISTS cost_ledger (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        agent_id TEXT,
        user_id TEXT,
        channel_id TEXT,
        model TEXT,
        input_tokens INTEGER,
        output_tokens INTEGER,
        cost_usd REAL NOT NULL,
        details TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_cost_user ON cost_ledger(user_id, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_cost_agent ON cost_ledger(agent_id, timestamp DESC);

    CREATE TABLE IF NOT EXISTS alert_definitions (
        id TEXT PRIMARY KEY,
        alert_type TEXT NOT NULL,
        metric_name TEXT NOT NULL,
        conditions TEXT NOT NULL,
        severity TEXT NOT NULL,
        notify TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS baselines (
        metric_key TEXT PRIMARY KEY,
        stats TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
"""


class GuardianDB:
    """SQLite database manager for Guardian."""

    def __init__(self, config: Optional[dict] = None):
        config = config or {}
        self.db_path = config.get(
            "db_path",
            os.environ.get("GUARDIAN_DB_PATH", DEFAULT_DB_PATH),
        )
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._setup_pragmas()
        self._create_tables()

    def _setup_pragmas(self):
        c = self._conn
        c.execute("PRAGMA journal_mode = WAL")
        c.execute("PRAGMA synchronous = NORMAL")
        c.execute("PRAGMA wal_autocheckpoint = 1000")
        c.execute("PRAGMA cache_size = -32000")
        c.execute("PRAGMA busy_timeout = 5000")
        c.execute("PRAGMA temp_store = MEMORY")

    def _create_tables(self):
        with self.cursor() as cur:
            cur.executescript(SCHEMA_SQL)

    @contextmanager
    def cursor(self):
        """Transaction-managed cursor."""
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                cur = self._conn.cursor()
                yield cur
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def read_cursor(self):
        """Non-locking read cursor."""
        return self._conn.cursor()

    def verify_integrity(self) -> dict:
        cur = self._conn.cursor()
        cur.execute("PRAGMA integrity_check")
        result = cur.fetchone()[0]
        if result != "ok":
            raise CorruptionError(f"Integrity check failed: {result}")
        return {"integrity": "ok"}

    def create_snapshot(self, target_path: str) -> dict:
        try:
            dst = sqlite3.connect(target_path)
            self._conn.backup(dst)
            dst.close()
            return {"success": True, "path": target_path, "size_bytes": os.path.getsize(target_path)}
        except Exception as e:
            raise StorageError(f"Snapshot failed: {e}")

    def close(self):
        try:
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._conn.close()
        except Exception:
            pass
