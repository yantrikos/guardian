"""Policy evaluator — rule compilation, matching, and evaluation.

Hot path: <5ms. All evaluation is in-memory against compiled rule indexes.
"""

import re
import json
import time
import uuid
import hashlib
import fnmatch
import logging
from typing import Optional, Any

from guardian_engine.db import GuardianDB
from guardian_engine.models import PolicyDecision, CompiledRule
from guardian_engine.errors import ValidationError

logger = logging.getLogger("guardian.policy")

VALID_EFFECTS = frozenset({"allow", "deny", "redact", "throttle", "warn"})
VALID_OPS = frozenset({"eq", "neq", "in", "not_in", "lt", "lte", "gt", "gte", "contains", "regex"})


class PolicyEvaluator:
    """In-memory policy engine. Compiled rules, priority-sorted, first-match-wins."""

    def __init__(self, db: GuardianDB, default_allow: bool = False):
        self._db = db
        self._default_allow = default_allow
        self._rules: list[CompiledRule] = []
        self._policy_version = ""
        self.reload()

    def reload(self):
        """Reload rules from database into memory."""
        cur = self._db.read_cursor()
        cur.execute(
            """SELECT r.*, p.name as policy_name, p.version as policy_version
               FROM rules r JOIN policies p ON r.policy_id = p.id
               WHERE r.is_active = 1 AND p.is_active = 1
               ORDER BY r.priority DESC"""
        )
        rules = []
        for row in cur.fetchall():
            rules.append(CompiledRule(
                id=row["id"],
                priority=row["priority"],
                effect=row["effect"],
                match=json.loads(row["match_def"]),
                where=json.loads(row["where_def"]) if row["where_def"] else None,
                config=json.loads(row["config"]) if row["config"] else {},
                reason=row["reason"] or "",
                policy_id=row["policy_id"],
                policy_version=row["policy_version"],
            ))
        self._rules = rules
        logger.info("Policy reloaded: %d rules", len(rules))

    @property
    def rules(self) -> list[CompiledRule]:
        return self._rules

    def evaluate(self, context: dict, action_type: str = "tool_call") -> PolicyDecision:
        """
        Evaluate context against all rules. First match wins.
        Returns PolicyDecision.
        """
        start = time.monotonic()

        for rule in self._rules:
            if self._matches(rule, context, action_type):
                latency = int((time.monotonic() - start) * 1_000_000)
                return PolicyDecision(
                    allowed=(rule.effect == "allow"),
                    effect=rule.effect,
                    rule_id=rule.id,
                    reason=rule.reason,
                    latency_us=latency,
                )

        # Default decision
        latency = int((time.monotonic() - start) * 1_000_000)
        return PolicyDecision(
            allowed=self._default_allow,
            effect="allow" if self._default_allow else "deny",
            reason="No matching rule (default)",
            latency_us=latency,
        )

    def _matches(self, rule: CompiledRule, context: dict, action_type: str) -> bool:
        """Check if a rule matches the given context."""
        match = rule.match

        if "action_type" in match and match["action_type"] != action_type:
            return False

        for field_name, expected in match.items():
            if field_name == "action_type":
                continue
            actual = context.get(field_name, "")
            if isinstance(expected, list):
                if not any(fnmatch.fnmatchcase(str(actual), str(e)) for e in expected):
                    return False
            elif isinstance(expected, str):
                if expected != "*" and not fnmatch.fnmatchcase(str(actual), expected):
                    return False

        if rule.where:
            return self._evaluate_where(rule.where, context)

        return True

    def _evaluate_where(self, where: dict, context: dict) -> bool:
        if "all" in where:
            return all(self._eval_cond(c, context) for c in where["all"])
        if "any" in where:
            return any(self._eval_cond(c, context) for c in where["any"])
        if "none" in where:
            return not any(self._eval_cond(c, context) for c in where["none"])
        return True

    def _eval_cond(self, cond: dict, context: dict) -> bool:
        field_path = cond.get("field", "")
        op = cond.get("op", "eq")
        expected = cond.get("value")

        # Resolve dot-path
        actual = context
        for part in field_path.split("."):
            if isinstance(actual, dict):
                actual = actual.get(part)
            else:
                actual = None
                break

        if op == "eq":
            return actual == expected
        elif op == "neq":
            return actual != expected
        elif op == "in":
            return actual in expected if isinstance(expected, (list, tuple)) else False
        elif op == "not_in":
            return actual not in expected if isinstance(expected, (list, tuple)) else True
        elif op == "lt":
            return actual < expected if actual is not None else False
        elif op == "lte":
            return actual <= expected if actual is not None else False
        elif op == "gt":
            return actual > expected if actual is not None else False
        elif op == "gte":
            return actual >= expected if actual is not None else False
        elif op == "contains":
            return expected in actual if isinstance(actual, str) else False
        elif op == "regex":
            return bool(re.search(expected, str(actual))) if actual else False
        return False

    def load_policy(self, content: str, name: str = "default", created_by: str = "system") -> dict:
        """Parse, validate, persist, and compile a policy."""
        try:
            try:
                import yaml
                policy = yaml.safe_load(content)
            except ImportError:
                policy = json.loads(content)
        except Exception as e:
            raise ValidationError(f"Failed to parse policy: {e}")

        version = str(policy.get("version", "1.0"))
        rules = policy.get("rules", [])
        policy_id = uuid.uuid4().hex[:24]
        now = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        for r in rules:
            effect = r.get("effect", "deny")
            if effect not in VALID_EFFECTS:
                raise ValidationError(f"Invalid effect '{effect}' in rule {r.get('id', '?')}")

        with self._db.cursor() as cur:
            cur.execute("UPDATE policies SET is_active = 0 WHERE name = ?", (name,))
            cur.execute(
                """INSERT INTO policies (id, name, version, content, hash, is_active, created_by, created_at)
                   VALUES (?, ?, ?, ?, ?, 1, ?, ?)""",
                (policy_id, name, version, content, content_hash, created_by, now),
            )
            for r in rules:
                rule_id = r.get("id", uuid.uuid4().hex[:24])
                cur.execute(
                    """INSERT INTO rules (id, policy_id, priority, effect, match_def, where_def, config, reason, is_active, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)""",
                    (rule_id, policy_id, r.get("priority", 0), r.get("effect", "deny"),
                     json.dumps(r.get("match", {})),
                     json.dumps(r.get("where")) if r.get("where") else None,
                     json.dumps(r.get("config", {})), r.get("reason", ""), now),
                )

        self.reload()
        return {"policy_id": policy_id, "version": version, "rules_loaded": len(rules)}
