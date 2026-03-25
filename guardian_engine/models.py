"""Guardian data models — all dataclasses used across modules."""

from dataclasses import dataclass, field
from typing import Optional, Any


@dataclass
class PolicyDecision:
    allowed: bool
    effect: str  # allow, deny, redact, throttle, warn
    rule_id: Optional[str] = None
    reason: str = ""
    redacted_content: Optional[str] = None
    retry_after_ms: int = 0
    latency_us: int = 0
    metadata: dict = field(default_factory=dict)


@dataclass
class CompiledRule:
    id: str
    priority: int
    effect: str
    match: dict
    where: Optional[dict] = None
    config: dict = field(default_factory=dict)
    reason: str = ""
    policy_id: str = ""
    policy_version: str = ""


@dataclass
class AuditEvent:
    event_id: str = ""
    timestamp: str = ""
    event_type: str = ""
    severity: str = "info"
    outcome: str = ""
    actor_type: str = ""
    actor_id: str = ""
    session_id: str = ""
    channel_id: str = ""
    tool: str = ""
    action: str = ""
    resource_type: str = ""
    resource_id: str = ""
    rule_id: str = ""
    policy_id: str = ""
    decision: str = ""
    reason: str = ""
    details: dict = field(default_factory=dict)
    correlation_id: str = ""
    latency_us: int = 0
    event_hash: str = ""
    prev_event_hash: str = ""


@dataclass
class AlertEvent:
    id: str = ""
    alert_type: str = ""
    severity: str = "warning"
    metric_name: str = ""
    metric_value: float = 0.0
    threshold: float = 0.0
    message: str = ""
    fired_at: str = ""
    acknowledged: bool = False
    resolved: bool = False


@dataclass
class MetricPoint:
    timestamp: float
    name: str
    value: float
    dimensions: dict = field(default_factory=dict)
