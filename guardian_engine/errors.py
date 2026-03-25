"""Guardian error hierarchy. Typed, machine-readable exceptions."""

from typing import Optional


class GuardianError(Exception):
    """Base exception for all Guardian errors."""
    code: str = "GUARDIAN_ERROR"
    retryable: bool = False

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.details = details or {}


class ValidationError(GuardianError):
    code = "GUARDIAN_VALIDATION_ERROR"


class PolicyDeniedError(GuardianError):
    code = "GUARDIAN_POLICY_DENIED"

    def __init__(self, message: str, rule_id: str = "", reason: str = ""):
        super().__init__(message, {"rule_id": rule_id, "reason": reason})
        self.rule_id = rule_id
        self.reason = reason


class RateLimitExceededError(GuardianError):
    code = "GUARDIAN_RATE_LIMIT"
    retryable = True

    def __init__(self, message: str, retry_after_ms: int = 0):
        super().__init__(message, {"retry_after_ms": retry_after_ms})
        self.retry_after_ms = retry_after_ms


class ContentBlockedError(GuardianError):
    code = "GUARDIAN_CONTENT_BLOCKED"

    def __init__(self, message: str, matched_patterns: list = None):
        super().__init__(message, {"matched_patterns": matched_patterns or []})
        self.matched_patterns = matched_patterns or []


class StorageError(GuardianError):
    code = "GUARDIAN_STORAGE_ERROR"
    retryable = True


class CorruptionError(StorageError):
    code = "GUARDIAN_CORRUPTION"
    retryable = False
