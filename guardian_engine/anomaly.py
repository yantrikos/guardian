"""Anomaly detection — streaming statistical methods.

Welford's online variance, EWMA, z-score, threshold alerting.
All stdlib-only, O(1) memory per metric.
"""

import math
import json
import logging
from typing import Optional

logger = logging.getLogger("guardian.anomaly")


class WelfordStats:
    """Online mean/variance using Welford's algorithm. O(1) memory."""
    __slots__ = ("count", "mean", "_m2")

    def __init__(self):
        self.count = 0
        self.mean = 0.0
        self._m2 = 0.0

    def update(self, value: float):
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self._m2 += delta * delta2

    @property
    def variance(self) -> float:
        return self._m2 / (self.count - 1) if self.count > 1 else 0.0

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)

    def zscore(self, value: float) -> float:
        if self.stddev == 0 or self.count < 10:
            return 0.0
        return (value - self.mean) / self.stddev

    def to_dict(self) -> dict:
        return {"count": self.count, "mean": self.mean, "stddev": self.stddev, "m2": self._m2}

    @classmethod
    def from_dict(cls, d: dict) -> "WelfordStats":
        s = cls()
        s.count = d.get("count", 0)
        s.mean = d.get("mean", 0.0)
        s._m2 = d.get("m2", 0.0)
        return s


class EWMA:
    """Exponentially Weighted Moving Average. O(1) memory."""
    __slots__ = ("alpha", "value", "initialized")

    def __init__(self, alpha: float = 0.1):
        self.alpha = alpha
        self.value = 0.0
        self.initialized = False

    def update(self, x: float):
        if not self.initialized:
            self.value = x
            self.initialized = True
        else:
            self.value = self.alpha * x + (1 - self.alpha) * self.value


class AnomalyDetector:
    """Streaming anomaly detection using z-score and EWMA."""

    def __init__(self):
        self._baselines: dict[str, WelfordStats] = {}
        self._ewma: dict[str, EWMA] = {}

    def update(self, metric_key: str, value: float):
        """Update baselines with a new value."""
        if metric_key not in self._baselines:
            self._baselines[metric_key] = WelfordStats()
            self._ewma[metric_key] = EWMA(alpha=0.1)
        self._baselines[metric_key].update(value)
        self._ewma[metric_key].update(value)

    def check_zscore(self, metric_key: str, value: float, threshold: float = 3.0) -> Optional[dict]:
        """Check if value is anomalous by z-score."""
        baseline = self._baselines.get(metric_key)
        if not baseline or baseline.count < 30:
            return None
        z = baseline.zscore(value)
        if abs(z) > threshold:
            return {
                "metric": metric_key,
                "value": value,
                "zscore": round(z, 3),
                "threshold": threshold,
                "mean": round(baseline.mean, 3),
                "stddev": round(baseline.stddev, 3),
            }
        return None

    def check_ewma_deviation(self, metric_key: str, value: float, factor: float = 2.0) -> Optional[dict]:
        """Check if value deviates significantly from EWMA."""
        ewma = self._ewma.get(metric_key)
        if not ewma or not ewma.initialized:
            return None
        if ewma.value == 0:
            return None
        ratio = abs(value - ewma.value) / max(abs(ewma.value), 1e-10)
        if ratio > factor:
            return {
                "metric": metric_key,
                "value": value,
                "ewma": round(ewma.value, 3),
                "deviation_factor": round(ratio, 3),
                "threshold_factor": factor,
            }
        return None

    def get_baseline(self, metric_key: str) -> Optional[dict]:
        b = self._baselines.get(metric_key)
        return b.to_dict() if b else None

    @property
    def tracked_count(self) -> int:
        return len(self._baselines)

    def persist_baselines(self) -> dict[str, dict]:
        """Export all baselines for persistence."""
        return {k: v.to_dict() for k, v in self._baselines.items()}

    def restore_baselines(self, data: dict[str, dict]):
        """Restore baselines from persisted data."""
        for k, v in data.items():
            self._baselines[k] = WelfordStats.from_dict(v)
