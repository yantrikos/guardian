"""Metrics collector — buffered time-series storage.

Non-blocking writes: metrics appended to in-memory deque,
flushed to SQLite periodically in batches.
"""

import time
import json
import logging
import collections
from typing import Optional, Any

from guardian_engine.db import GuardianDB
from guardian_engine.models import MetricPoint

logger = logging.getLogger("guardian.metrics")


class MetricsCollector:
    """High-throughput metrics collection with buffered persistence."""

    def __init__(self, db: GuardianDB, buffer_max: int = 100_000):
        self._db = db
        self._buffer: collections.deque = collections.deque(maxlen=buffer_max)
        self._counter = 0

    def record(self, name: str, value: float, dimensions: Optional[dict] = None):
        """Non-blocking: append to in-memory buffer."""
        self._buffer.append(MetricPoint(
            timestamp=time.time(),
            name=name,
            value=value,
            dimensions=dimensions or {},
        ))
        self._counter += 1

    def flush(self) -> int:
        """Batch-write buffered metrics to SQLite."""
        points = []
        while self._buffer:
            points.append(self._buffer.popleft())

        if not points:
            return 0

        now = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        with self._db.cursor() as cur:
            cur.executemany(
                """INSERT INTO metrics (timestamp, metric_name, value, dimensions, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                [(
                    time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(mp.timestamp)),
                    mp.name, mp.value,
                    json.dumps(mp.dimensions) if mp.dimensions else None,
                    now,
                ) for mp in points],
            )

        return len(points)

    def query(
        self,
        metric_name: str,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: int = 1000,
    ) -> list[dict]:
        """Query raw metrics."""
        query = "SELECT * FROM metrics WHERE metric_name = ?"
        params: list[Any] = [metric_name]

        if since:
            query += " AND timestamp >= ?"
            params.append(since)
        if until:
            query += " AND timestamp <= ?"
            params.append(until)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cur = self._db.read_cursor()
        cur.execute(query, params)
        return [dict(row) for row in cur.fetchall()]

    def rollup(self, older_than_hours: int = 24, bucket_minutes: int = 15) -> int:
        """Compact raw metrics into rollup aggregates."""
        cutoff = time.strftime(
            "%Y-%m-%dT%H:%M:%S",
            time.gmtime(time.time() - older_than_hours * 3600),
        )
        now = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())

        with self._db.cursor() as cur:
            # Get distinct metric names before cutoff
            cur.execute(
                "SELECT DISTINCT metric_name FROM metrics WHERE timestamp < ?",
                (cutoff,),
            )
            metric_names = [row["metric_name"] for row in cur.fetchall()]

            rolled = 0
            for name in metric_names:
                cur.execute(
                    """SELECT
                        COUNT(*) as cnt,
                        SUM(value) as sum_val,
                        MIN(value) as min_val,
                        MAX(value) as max_val,
                        AVG(value) as avg_val
                       FROM metrics
                       WHERE metric_name = ? AND timestamp < ?""",
                    (name, cutoff),
                )
                row = cur.fetchone()
                if row and row["cnt"] > 0:
                    cur.execute(
                        """INSERT INTO metrics_rollup
                           (period_start, period_end, metric_name, dimensions,
                            count, sum_val, min_val, max_val, avg_val, created_at)
                           VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?)""",
                        (cutoff, now, name, row["cnt"], row["sum_val"],
                         row["min_val"], row["max_val"], row["avg_val"], now),
                    )
                    rolled += row["cnt"]

            # Delete compacted raw metrics
            cur.execute("DELETE FROM metrics WHERE timestamp < ?", (cutoff,))

        return rolled

    @property
    def buffer_depth(self) -> int:
        return len(self._buffer)

    @property
    def total_recorded(self) -> int:
        return self._counter
