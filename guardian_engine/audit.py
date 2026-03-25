"""Audit logger — immutable, append-only, tamper-evident.

Chained SHA-256 hashes for integrity verification.
Buffered writes for non-blocking hot path.
"""

import json
import time
import uuid
import hashlib
import logging
import collections
from typing import Optional, Any

from guardian_engine.db import GuardianDB
from guardian_engine.models import AuditEvent

logger = logging.getLogger("guardian.audit")


class AuditLogger:
    """Immutable audit log with tamper-evident hash chain."""

    def __init__(self, db: GuardianDB, buffer_max: int = 50_000):
        self._db = db
        self._buffer: collections.deque = collections.deque(maxlen=buffer_max)
        self._last_hash: str = "0" * 64
        self._event_count: int = 0

        # Restore last hash from DB
        cur = db.read_cursor()
        cur.execute("SELECT event_hash FROM audit_log ORDER BY timestamp DESC LIMIT 1")
        row = cur.fetchone()
        if row:
            self._last_hash = row["event_hash"]

    def log(self, **kwargs) -> AuditEvent:
        """
        Enqueue an audit event (non-blocking).

        Accepted kwargs match AuditEvent fields:
        event_type, severity, outcome, actor_type, actor_id,
        session_id, channel_id, tool, action, resource_type,
        resource_id, rule_id, policy_id, decision, reason,
        details, correlation_id, latency_us
        """
        event_id = uuid.uuid4().hex[:24]
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + \
            f".{int(time.time() * 1000) % 1000:03d}"

        # Tamper-evident chain
        raw = f"{self._last_hash}:{event_id}:{timestamp}:{kwargs.get('event_type', '')}"
        event_hash = hashlib.sha256(raw.encode()).hexdigest()

        event = AuditEvent(
            event_id=event_id,
            timestamp=timestamp,
            event_hash=event_hash,
            prev_event_hash=self._last_hash,
            **{k: v for k, v in kwargs.items() if k in AuditEvent.__dataclass_fields__},
        )
        self._last_hash = event_hash
        self._event_count += 1
        self._buffer.append(event)
        return event

    def flush(self):
        """Persist buffered events to SQLite."""
        events = []
        while self._buffer:
            events.append(self._buffer.popleft())

        if not events:
            return 0

        with self._db.cursor() as cur:
            for ae in events:
                cur.execute(
                    """INSERT INTO audit_log
                       (id, timestamp, event_type, severity, outcome,
                        actor_type, actor_id, session_id, channel_id, tool,
                        action, resource_type, resource_id, rule_id, policy_id,
                        decision, reason, details, correlation_id, latency_us,
                        event_hash, prev_event_hash)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (ae.event_id, ae.timestamp, ae.event_type, ae.severity, ae.outcome,
                     ae.actor_type, ae.actor_id, ae.session_id, ae.channel_id, ae.tool,
                     ae.action, ae.resource_type, ae.resource_id, ae.rule_id, ae.policy_id,
                     ae.decision, ae.reason,
                     json.dumps(ae.details) if ae.details else None,
                     ae.correlation_id, ae.latency_us, ae.event_hash, ae.prev_event_hash),
                )

        return len(events)

    def query(
        self,
        event_type: Optional[str] = None,
        actor_id: Optional[str] = None,
        session_id: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query the audit log."""
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: list[Any] = []

        if event_type:
            query += " AND event_type LIKE ?"
            params.append(event_type.replace("*", "%"))
        if actor_id:
            query += " AND actor_id = ?"
            params.append(actor_id)
        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        if since:
            query += " AND timestamp >= ?"
            params.append(since)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cur = self._db.read_cursor()
        cur.execute(query, params)
        return [dict(row) for row in cur.fetchall()]

    def verify_chain(self, limit: int = 1000) -> dict:
        """Verify the hash chain integrity of the audit log."""
        cur = self._db.read_cursor()
        cur.execute("SELECT * FROM audit_log ORDER BY rowid ASC LIMIT ?", (limit,))

        prev_hash = "0" * 64
        verified = 0
        broken_at = None

        for row in cur.fetchall():
            expected_raw = f"{row['prev_event_hash']}:{row['id']}:{row['timestamp']}:{row['event_type']}"
            expected_hash = hashlib.sha256(expected_raw.encode()).hexdigest()

            if row["event_hash"] != expected_hash:
                broken_at = row["id"]
                break
            if row["prev_event_hash"] != prev_hash:
                broken_at = row["id"]
                break

            prev_hash = row["event_hash"]
            verified += 1

        return {
            "verified": verified,
            "integrity": "ok" if broken_at is None else "broken",
            "broken_at": broken_at,
        }

    @property
    def buffer_depth(self) -> int:
        return len(self._buffer)

    @property
    def total_events(self) -> int:
        return self._event_count
