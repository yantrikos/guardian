"""Alert manager — fire, debounce, acknowledge, resolve."""

import time
import uuid
import json
import logging
from typing import Optional

from guardian_engine.db import GuardianDB
from guardian_engine.models import AlertEvent

logger = logging.getLogger("guardian.alerts")

COOLDOWN_SECONDS = 300  # 5 minute debounce per alert definition


class AlertManager:
    """Manages alert lifecycle: fire, debounce, acknowledge, resolve."""

    def __init__(self, db: GuardianDB):
        self._db = db
        self._last_fired: dict[str, float] = {}  # definition_id -> timestamp

    def fire(self, alert: AlertEvent) -> bool:
        """Fire an alert. Returns False if debounced."""
        # Debounce check
        key = f"{alert.alert_type}:{alert.metric_name}"
        now = time.time()
        last = self._last_fired.get(key, 0)
        if (now - last) < COOLDOWN_SECONDS:
            return False

        self._last_fired[key] = now

        if not alert.id:
            alert.id = uuid.uuid4().hex[:24]
        if not alert.fired_at:
            alert.fired_at = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())

        with self._db.cursor() as cur:
            cur.execute(
                """INSERT INTO alerts
                   (id, alert_type, severity, metric_name, metric_value,
                    threshold, message, fired_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (alert.id, alert.alert_type, alert.severity,
                 alert.metric_name, alert.metric_value, alert.threshold,
                 alert.message, alert.fired_at),
            )

        logger.warning("Alert fired: [%s] %s", alert.severity, alert.message)
        return True

    def acknowledge(self, alert_id: str, by: str = "") -> bool:
        now = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        with self._db.cursor() as cur:
            cur.execute(
                "UPDATE alerts SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ? WHERE id = ?",
                (by, now, alert_id),
            )
            return cur.rowcount > 0

    def resolve(self, alert_id: str) -> bool:
        now = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        with self._db.cursor() as cur:
            cur.execute(
                "UPDATE alerts SET resolved = 1, resolved_at = ? WHERE id = ?",
                (now, alert_id),
            )
            return cur.rowcount > 0

    def get_active(self, limit: int = 50) -> list[dict]:
        cur = self._db.read_cursor()
        cur.execute(
            "SELECT * FROM alerts WHERE resolved = 0 ORDER BY fired_at DESC LIMIT ?",
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]

    def get_all(self, limit: int = 100, include_resolved: bool = True) -> list[dict]:
        cur = self._db.read_cursor()
        if include_resolved:
            cur.execute("SELECT * FROM alerts ORDER BY fired_at DESC LIMIT ?", (limit,))
        else:
            cur.execute(
                "SELECT * FROM alerts WHERE resolved = 0 ORDER BY fired_at DESC LIMIT ?",
                (limit,),
            )
        return [dict(row) for row in cur.fetchall()]
