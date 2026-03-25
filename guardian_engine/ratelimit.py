"""Rate limiter — token bucket with in-memory counters."""

import time
import logging
from typing import Optional

logger = logging.getLogger("guardian.ratelimit")


class TokenBucket:
    """Token bucket rate limiter. O(1) per check."""
    __slots__ = ("capacity", "tokens", "refill_rate", "last_refill")

    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.tokens = float(capacity)
        self.refill_rate = refill_rate
        self.last_refill = time.monotonic()

    def try_consume(self, count: int = 1) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        if self.tokens >= count:
            self.tokens -= count
            return True
        return False

    def retry_after_ms(self) -> int:
        if self.tokens >= 1:
            return 0
        deficit = 1 - self.tokens
        return int((deficit / self.refill_rate) * 1000) + 1

    def to_dict(self) -> dict:
        return {
            "capacity": self.capacity,
            "tokens": round(self.tokens, 2),
            "refill_rate": self.refill_rate,
        }


class RateLimiter:
    """Manages multiple rate limit buckets keyed by scope."""

    def __init__(self):
        self._buckets: dict[str, TokenBucket] = {}

    def check(self, key: str, capacity: int = 100, window_seconds: int = 60) -> tuple[bool, int]:
        """
        Check rate limit for a key.
        Returns (allowed, retry_after_ms).
        """
        if key not in self._buckets:
            self._buckets[key] = TokenBucket(
                capacity=capacity,
                refill_rate=capacity / max(window_seconds, 1),
            )

        bucket = self._buckets[key]
        if bucket.try_consume():
            return True, 0
        return False, bucket.retry_after_ms()

    def get_bucket(self, key: str) -> Optional[TokenBucket]:
        return self._buckets.get(key)

    @property
    def active_count(self) -> int:
        return len(self._buckets)

    def cleanup_stale(self, max_idle_seconds: float = 3600):
        """Remove buckets that have been idle and fully refilled."""
        now = time.monotonic()
        stale = [
            k for k, b in self._buckets.items()
            if (now - b.last_refill) > max_idle_seconds and b.tokens >= b.capacity
        ]
        for k in stale:
            del self._buckets[k]

    @staticmethod
    def build_key(context: dict, scope: str = "user") -> str:
        """Build a rate limit key from context and scope."""
        scope_id = context.get(f"{scope}_id", context.get("user_id", "global"))
        tool = context.get("tool", "*")
        return f"rate:{scope}:{scope_id}:{tool}"
