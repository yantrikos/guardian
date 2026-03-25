"""
Guardian Engine — Main orchestrator.

Composes: PolicyEvaluator, ContentFilter, RateLimiter,
MetricsCollector, AnomalyDetector, AuditLogger, AlertManager, CostTracker.

Provides the unified public API for the bridge and TypeScript layer.
"""

import os
import time
import json
import logging
import threading
from typing import Optional

from guardian_engine.db import GuardianDB
from guardian_engine.policy import PolicyEvaluator
from guardian_engine.content import ContentFilter
from guardian_engine.ratelimit import RateLimiter
from guardian_engine.metrics import MetricsCollector
from guardian_engine.anomaly import AnomalyDetector
from guardian_engine.audit import AuditLogger
from guardian_engine.alerts import AlertManager
from guardian_engine.cost import CostTracker
from guardian_engine.models import PolicyDecision, AlertEvent

logger = logging.getLogger("guardian")

FLUSH_INTERVAL = 1.0  # seconds


class GuardianEngine:
    """
    Unified security engine for OpenClaw.

    Hot path (<5ms): check_tool, check_content, check_secret_access
    Cold path (async): metrics, audit persistence, anomaly detection
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}

        # Initialize database
        self.db = GuardianDB(self.config)

        # Initialize subsystems
        self.policy = PolicyEvaluator(self.db, default_allow=self.config.get("default_allow", False))
        self.content = ContentFilter(custom_patterns=self.config.get("custom_patterns"))
        self.rate_limiter = RateLimiter()
        self.metrics = MetricsCollector(self.db)
        self.anomaly = AnomalyDetector()
        self.audit = AuditLogger(self.db)
        self.alerts = AlertManager(self.db)
        self.cost = CostTracker(self.db)

        # Background flush
        self._running = True
        self._flush_timer = None
        self._start_flush()

        logger.info(
            "GuardianEngine initialized (rules=%d, db=%s)",
            len(self.policy.rules), self.db.db_path,
        )

    # ── Hot Path API ───────────────────────────────────────────────────

    def check_tool(self, context: dict) -> PolicyDecision:
        """Check if a tool call is allowed. <5ms."""
        start = time.monotonic()

        # Rate limit
        for rule in self.policy.rules:
            if rule.effect == "throttle" and self.policy._matches(rule, context, "tool_call"):
                limits = rule.config.get("limits", {})
                key = RateLimiter.build_key(context, limits.get("scope", "user"))
                allowed, retry_ms = self.rate_limiter.check(
                    key,
                    capacity=limits.get("max_calls", 100),
                    window_seconds=limits.get("window_seconds", 60),
                )
                if not allowed:
                    latency = int((time.monotonic() - start) * 1_000_000)
                    self.audit.log(
                        event_type="tool.rate_limited", severity="warning",
                        outcome="throttled", actor_id=context.get("user_id", ""),
                        tool=context.get("tool", ""),
                        details={"retry_after_ms": retry_ms},
                        latency_us=latency,
                    )
                    self.metrics.record("rate_limit.denied", 1, {"tool": context.get("tool", "")})
                    return PolicyDecision(
                        allowed=False, effect="throttle",
                        reason="Rate limit exceeded",
                        retry_after_ms=retry_ms, latency_us=latency,
                    )

        # Policy evaluation
        decision = self.policy.evaluate(context, "tool_call")
        decision.latency_us = int((time.monotonic() - start) * 1_000_000)

        self.audit.log(
            event_type="tool.policy_check",
            severity="warning" if not decision.allowed else "info",
            outcome="allowed" if decision.allowed else "denied",
            actor_id=context.get("user_id", ""),
            tool=context.get("tool", ""),
            session_id=context.get("session_id", ""),
            channel_id=context.get("channel_id", ""),
            rule_id=decision.rule_id or "",
            decision=decision.effect,
            reason=decision.reason,
            latency_us=decision.latency_us,
        )
        self.metrics.record("policy.decisions", 1, {"effect": decision.effect})
        return decision

    def check_content(self, content: str, context: dict) -> PolicyDecision:
        """Check content for injection (inbound) or PII/DLP (outbound). <5ms."""
        direction = context.get("direction", "inbound")

        if direction == "inbound":
            decision = self.content.check_inbound(content)
        else:
            decision = self.content.check_outbound(content)

        if not decision.allowed:
            self.audit.log(
                event_type="content.filtered",
                severity="critical" if decision.effect == "deny" else "warning",
                outcome="blocked" if decision.effect == "deny" else "redacted",
                actor_id=context.get("user_id", ""),
                channel_id=context.get("channel_id", ""),
                details={"direction": direction, "matched": decision.metadata.get("matched_patterns", [])},
                latency_us=decision.latency_us,
            )
            self.metrics.record("content.filtered", 1, {"direction": direction, "effect": decision.effect})

        return decision

    def check_secret_access(self, secret_name: str, context: dict) -> PolicyDecision:
        """Check if access to a secret is allowed."""
        decision = self.policy.evaluate(
            {**context, "resource_type": "secret", "resource_id": secret_name},
            "secret_access",
        )
        self.audit.log(
            event_type="secret.access",
            severity="info" if decision.allowed else "critical",
            outcome="allowed" if decision.allowed else "denied",
            actor_id=context.get("agent_id", ""),
            resource_type="secret", resource_id=secret_name,
            rule_id=decision.rule_id or "",
            latency_us=decision.latency_us,
        )
        return decision

    def check_cost_limit(self, context: dict) -> PolicyDecision:
        """Check if cost limits are exceeded."""
        for rule in self.policy.rules:
            if rule.match.get("action_type") == "cost_limit":
                limits = rule.config.get("limits", {})
                scope = limits.get("scope", "user")
                scope_id = context.get(f"{scope}_id", "")
                max_cost = limits.get("max_cost_usd", float("inf"))
                return self.cost.check_limit(scope, scope_id, max_cost)
        return PolicyDecision(allowed=True, effect="allow", reason="No cost limits defined")

    # ── Cold Path API ──────────────────────────────────────────────────

    def record_metric(self, name: str, value: float, dimensions: dict = None):
        """Record a metric and update anomaly baselines."""
        self.metrics.record(name, value, dimensions)
        key = f"{name}:{json.dumps(dimensions or {}, sort_keys=True)}"
        self.anomaly.update(key, value)

    def record_cost(self, **kwargs):
        """Record a model call cost."""
        self.cost.record(**kwargs)
        self.metrics.record("cost.usd", kwargs.get("cost_usd", 0), {"model": kwargs.get("model", "")})

    def load_policy(self, content: str, name: str = "default", created_by: str = "system") -> dict:
        """Load and compile a policy."""
        result = self.policy.load_policy(content, name, created_by)
        self.audit.log(
            event_type="policy.loaded", severity="info", outcome="success",
            actor_type="system", actor_id=created_by,
            details=result,
        )
        return result

    # ── Maintenance ────────────────────────────────────────────────────

    def flush(self):
        """Flush all buffers to SQLite."""
        self.audit.flush()
        self.metrics.flush()
        self.cost.flush()

    def run_maintenance(self) -> dict:
        """Periodic maintenance: flush, check anomalies, persist baselines."""
        self.flush()

        # Persist anomaly baselines
        baselines = self.anomaly.persist_baselines()
        with self.db.cursor() as cur:
            now = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
            for key, stats in baselines.items():
                cur.execute(
                    "INSERT OR REPLACE INTO baselines (metric_key, stats, updated_at) VALUES (?, ?, ?)",
                    (key, json.dumps(stats), now),
                )

        # Cleanup stale rate limiters
        self.rate_limiter.cleanup_stale()

        return {
            "flushed": True,
            "baselines_persisted": len(baselines),
            "rate_limiters_cleaned": self.rate_limiter.active_count,
        }

    # ── Background Flush ───────────────────────────────────────────────

    def _start_flush(self):
        if not self._running:
            return
        self._flush_timer = threading.Timer(FLUSH_INTERVAL, self._periodic_flush)
        self._flush_timer.daemon = True
        self._flush_timer.start()

    def _periodic_flush(self):
        try:
            self.flush()
        except Exception as e:
            logger.error("Periodic flush failed: %s", e)
        if self._running:
            self._start_flush()

    # ── Stats & Health ─────────────────────────────────────────────────

    def stats(self) -> dict:
        cur = self.db.read_cursor()

        cur.execute("SELECT COUNT(*) as c FROM audit_log")
        audit_count = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) as c FROM metrics")
        metrics_count = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) as c FROM alerts WHERE resolved = 0")
        active_alerts = cur.fetchone()["c"]

        db_size = os.path.getsize(self.db.db_path) if os.path.exists(self.db.db_path) else 0

        return {
            "active_rules": len(self.policy.rules),
            "audit_events": audit_count,
            "metrics_recorded": metrics_count,
            "active_alerts": active_alerts,
            "total_cost_usd": self.cost.get_total_cost(),
            "db_size_bytes": db_size,
            "rate_limiters_active": self.rate_limiter.active_count,
            "anomaly_baselines": self.anomaly.tracked_count,
            "audit_buffer": self.audit.buffer_depth,
            "metrics_buffer": self.metrics.buffer_depth,
        }

    def health_check(self) -> dict:
        try:
            integrity = self.db.verify_integrity()
            stats = self.stats()
            return {
                "healthy": True,
                "engine": "guardian",
                "active_rules": stats["active_rules"],
                "active_alerts": stats["active_alerts"],
            }
        except Exception as e:
            return {"healthy": False, "engine": "guardian", "error": str(e)}

    # ── Lifecycle ──────────────────────────────────────────────────────

    def close(self):
        self._running = False
        if self._flush_timer:
            self._flush_timer.cancel()
        try:
            self.flush()
        except Exception:
            pass
        self.db.close()
        logger.info("GuardianEngine closed")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
