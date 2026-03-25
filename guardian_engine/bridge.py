#!/usr/bin/env python3
"""Guardian Bridge — JSON stdin/stdout interface for TypeScript plugin."""

import sys
import json
import signal

from guardian_engine.engine import GuardianEngine

_engine: GuardianEngine = None


def get_engine(config: dict = None) -> GuardianEngine:
    global _engine
    if _engine is None:
        _engine = GuardianEngine(config)
    return _engine


def handle_command(command: str, args: dict, config: dict) -> dict:
    engine = get_engine(config)
    try:
        if command == "check_tool":
            d = engine.check_tool(args.get("context", {}))
            return {"success": True, "allowed": d.allowed, "effect": d.effect, "reason": d.reason,
                    "rule_id": d.rule_id, "retry_after_ms": d.retry_after_ms, "latency_us": d.latency_us}

        elif command == "check_content":
            d = engine.check_content(args.get("content", ""), args.get("context", {}))
            return {"success": True, "allowed": d.allowed, "effect": d.effect, "reason": d.reason,
                    "redacted_content": d.redacted_content, "matched_patterns": d.metadata.get("matched_patterns", [])}

        elif command == "check_secret":
            d = engine.check_secret_access(args.get("secret_name", ""), args.get("context", {}))
            return {"success": True, "allowed": d.allowed, "effect": d.effect, "reason": d.reason}

        elif command == "check_cost":
            d = engine.check_cost_limit(args.get("context", {}))
            return {"success": True, "allowed": d.allowed, "effect": d.effect, "reason": d.reason,
                    "metadata": d.metadata}

        elif command == "load_policy":
            r = engine.load_policy(args.get("content", ""), args.get("name", "default"), args.get("created_by", "system"))
            return {"success": True, **r}

        elif command == "record_metric":
            engine.record_metric(args.get("name", ""), args.get("value", 0), args.get("dimensions"))
            return {"success": True}

        elif command == "record_cost":
            engine.record_cost(**{k: v for k, v in args.items() if k != "command"})
            return {"success": True}

        elif command == "get_audit":
            events = engine.audit.query(
                event_type=args.get("event_type"), actor_id=args.get("actor_id"),
                session_id=args.get("session_id"), since=args.get("since"),
                limit=args.get("limit", 100))
            return {"success": True, "events": events}

        elif command == "get_alerts":
            alerts = engine.alerts.get_active(args.get("limit", 50))
            return {"success": True, "alerts": alerts}

        elif command == "acknowledge_alert":
            ok = engine.alerts.acknowledge(args["alert_id"], args.get("by", ""))
            return {"success": ok}

        elif command == "resolve_alert":
            ok = engine.alerts.resolve(args["alert_id"])
            return {"success": ok}

        elif command == "stats":
            return {"success": True, **engine.stats()}

        elif command == "health_check":
            return engine.health_check()

        elif command == "maintenance":
            return {"success": True, **engine.run_maintenance()}

        elif command == "verify_audit_chain":
            result = engine.audit.verify_chain(args.get("limit", 1000))
            return {"success": True, **result}

        elif command == "get_policies":
            cur = engine.db.read_cursor()
            cur.execute("SELECT id, name, version, hash, created_at FROM policies WHERE is_active = 1")
            return {"success": True, "policies": [dict(row) for row in cur.fetchall()]}

        else:
            return {"success": False, "error": f"Unknown command: {command}"}

    except Exception as e:
        return {"success": False, "error": str(e), "code": getattr(e, "code", "GUARDIAN_ERROR")}


def main():
    if "--persistent" in sys.argv:
        def shutdown(sig, frame):
            if _engine:
                _engine.close()
            sys.exit(0)
        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                result = handle_command(data.get("command", ""), data.get("args", {}), data.get("config", {}))
                result["request_id"] = data.get("request_id")
                print(json.dumps(result), flush=True)
            except Exception as e:
                print(json.dumps({"success": False, "error": str(e)}), flush=True)
        if _engine:
            _engine.close()
    else:
        try:
            data = json.loads(sys.stdin.read())
        except json.JSONDecodeError:
            print(json.dumps({"success": False, "error": "Invalid JSON"}))
            return
        result = handle_command(data.get("command", ""), data.get("args", {}), data.get("config", {}))
        print(json.dumps(result))


if __name__ == "__main__":
    main()
