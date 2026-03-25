"""Content filter — PII detection, prompt injection, DLP.

Pre-compiled regex patterns for <5ms evaluation.
"""

import re
import time
import logging
from typing import Optional

from guardian_engine.models import PolicyDecision

logger = logging.getLogger("guardian.content")

# ── Built-in Patterns ──────────────────────────────────────────────────────

BUILTIN_PATTERNS = {
    # PII
    "email": re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b'),
    "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "credit_card": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
    "phone_us": re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),

    # Secrets / DLP
    "api_key": re.compile(r'(?i)(?:api[_\-]?key|apikey|api_secret)["\s:=]+["\']?[A-Za-z0-9_\-]{20,}'),
    "bearer_token": re.compile(r'Bearer\s+[A-Za-z0-9_\-\.]{20,}'),
    "private_key": re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----'),
    "password_in_url": re.compile(r'://[^:]+:[^@]+@'),
    "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "jwt": re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
    "github_token": re.compile(r'gh[ps]_[A-Za-z0-9_]{36,}'),
    "slack_token": re.compile(r'xox[bpras]-[A-Za-z0-9\-]{10,}'),

    # Prompt injection / Jailbreak
    "prompt_injection": re.compile(
        r'(?i)(?:ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions'
        r'|you\s+are\s+now|new\s+instructions?\s*:'
        r'|system\s*:\s*|reveal\s+(?:your\s+)?(?:system\s+)?prompt'
        r'|bypass\s+(?:all\s+)?(?:security|policy|filter)'
        r'|developer\s+mode\s*:'
        r'|forget\s+(?:all\s+)?(?:previous|prior)\s+(?:context|instructions))'
    ),
    "jailbreak": re.compile(
        r'(?i)(?:DAN\s+mode|do\s+anything\s+now'
        r'|act\s+as\s+(?:if\s+)?you\s+(?:have\s+)?no\s+(?:limits|restrictions)'
        r'|pretend\s+(?:you\s+(?:are|have)\s+)?no\s+(?:rules|restrictions|guidelines))'
    ),
}

# Categories for filtering
PII_PATTERNS = {"email", "ssn", "credit_card", "phone_us"}
DLP_PATTERNS = {"api_key", "bearer_token", "private_key", "password_in_url", "aws_key", "jwt", "github_token", "slack_token"}
INJECTION_PATTERNS = {"prompt_injection", "jailbreak"}


class ContentFilter:
    """Content filtering engine with pre-compiled regex patterns."""

    def __init__(self, custom_patterns: Optional[dict] = None):
        self._patterns = dict(BUILTIN_PATTERNS)
        if custom_patterns:
            for name, pattern_str in custom_patterns.items():
                try:
                    self._patterns[f"custom:{name}"] = re.compile(pattern_str, re.IGNORECASE)
                except re.error as e:
                    logger.warning("Invalid custom pattern '%s': %s", name, e)

    def check_inbound(self, content: str) -> PolicyDecision:
        """Check inbound content for prompt injection / jailbreak."""
        start = time.monotonic()
        matched = []

        for name in INJECTION_PATTERNS:
            if self._patterns[name].search(content):
                matched.append(name)

        latency = int((time.monotonic() - start) * 1_000_000)

        if matched:
            return PolicyDecision(
                allowed=False,
                effect="deny",
                reason=f"Prompt injection detected: {', '.join(matched)}",
                latency_us=latency,
                metadata={"matched_patterns": matched, "direction": "inbound"},
            )

        return PolicyDecision(allowed=True, effect="allow", reason="Clean", latency_us=latency)

    def check_outbound(self, content: str) -> PolicyDecision:
        """Check outbound content for PII and secrets (DLP)."""
        start = time.monotonic()
        matched = []

        for name in PII_PATTERNS | DLP_PATTERNS:
            if name in self._patterns and self._patterns[name].search(content):
                matched.append(name)

        # Check custom patterns
        for name, pattern in self._patterns.items():
            if name.startswith("custom:") and pattern.search(content):
                matched.append(name)

        latency = int((time.monotonic() - start) * 1_000_000)

        if not matched:
            return PolicyDecision(allowed=True, effect="allow", reason="Clean", latency_us=latency)

        # Redact matched content
        redacted = content
        for name in matched:
            clean_name = name.replace("custom:", "")
            if clean_name in self._patterns:
                redacted = self._patterns[clean_name].sub(f"[{name.upper()}_REDACTED]", redacted)

        return PolicyDecision(
            allowed=False,
            effect="redact",
            reason=f"DLP/PII matched: {', '.join(matched)}",
            redacted_content=redacted,
            latency_us=latency,
            metadata={"matched_patterns": matched, "direction": "outbound"},
        )

    def scan(self, content: str, categories: Optional[set] = None) -> list[str]:
        """Scan content against all or specific pattern categories. Returns matched pattern names."""
        check_patterns = categories or set(self._patterns.keys())
        matched = []
        for name in check_patterns:
            if name in self._patterns and self._patterns[name].search(content):
                matched.append(name)
        return matched
