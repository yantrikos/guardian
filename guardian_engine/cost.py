"""Cost tracker — per-agent/user/model cost tracking with daily limits."""

import time
import json
import logging
from typing import Optional

from guardian_engine.db import GuardianDB
from guardian_engine.models import PolicyDecision

logger = logging.getLogger("guardian.cost")


class CostTracker:
    """In-memory cost counters with periodic persistence."""

    def __init__(self, db: GuardianDB):
        self._db = db
        self._counters: dict[str, float] = {}  # "daily:{scope}:{id}:{date}" -> cost
        self._pending: list[dict] = []

    def record(
        self,
        agent_id: str,
        user_id: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        channel_id: str = "",
    ):
        """Record a model call cost."""
        day = time.strftime("%Y-%m-%d")
        for scope, sid in [("user", user_id), ("agent", agent_id)]:
            key = f"daily:{scope}:{sid}:{day}"
            self._counters[key] = self._counters.get(key, 0.0) + cost_usd

        self._pending.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "agent_id": agent_id,
            "user_id": user_id,
            "channel_id": channel_id,
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": cost_usd,
        })

    def check_limit(self, scope: str, scope_id: str, max_cost_usd: float) -> PolicyDecision:
        """Check if daily cost limit exceeded."""
        day = time.strftime("%Y-%m-%d")
        key = f"daily:{scope}:{scope_id}:{day}"
        current = self._counters.get(key, 0.0)

        if current >= max_cost_usd:
            return PolicyDecision(
                allowed=False,
                effect="deny",
                reason=f"Daily cost limit ${max_cost_usd:.2f} exceeded (current: ${current:.2f})",
                metadata={"current_cost": current, "limit": max_cost_usd},
            )
        return PolicyDecision(
            allowed=True,
            effect="allow",
            reason="Within cost limits",
            metadata={"current_cost": current, "limit": max_cost_usd},
        )

    def get_daily_cost(self, scope: str, scope_id: str) -> float:
        day = time.strftime("%Y-%m-%d")
        key = f"daily:{scope}:{scope_id}:{day}"
        return self._counters.get(key, 0.0)

    def flush(self) -> int:
        """Persist pending cost events to SQLite."""
        if not self._pending:
            return 0

        events = list(self._pending)
        self._pending.clear()

        with self._db.cursor() as cur:
            for e in events:
                cur.execute(
                    """INSERT INTO cost_ledger
                       (timestamp, agent_id, user_id, channel_id, model,
                        input_tokens, output_tokens, cost_usd, details)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)""",
                    (e["timestamp"], e["agent_id"], e["user_id"],
                     e["channel_id"], e["model"], e["input_tokens"],
                     e["output_tokens"], e["cost_usd"]),
                )

        return len(events)

    def get_total_cost(self) -> float:
        cur = self._db.read_cursor()
        cur.execute("SELECT COALESCE(SUM(cost_usd), 0) as total FROM cost_ledger")
        return cur.fetchone()["total"]

    def get_cost_by_model(self, limit: int = 10) -> list[dict]:
        cur = self._db.read_cursor()
        cur.execute(
            """SELECT model, SUM(cost_usd) as total, COUNT(*) as calls,
                      SUM(input_tokens) as input_tok, SUM(output_tokens) as output_tok
               FROM cost_ledger GROUP BY model ORDER BY total DESC LIMIT ?""",
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]
