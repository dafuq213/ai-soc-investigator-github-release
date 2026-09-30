"""Select a Wazuh alert that has not already been investigated locally.

This is an operator convenience, not an LLM tool.  It only reads bounded
Wazuh alert summaries and local JSON artifacts, then returns an alert ID for
the normal evidence-first investigation command.  It never calls a model.
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any, Iterable, Mapping

try:
    from .alert_scope import AlertScope
    from .normalized_alert import normalize_alert
    from .wazuh_tools import WazuhConfig, WazuhToolLayer
except ImportError:
    from alert_scope import AlertScope
    from normalized_alert import normalize_alert
    from wazuh_tools import WazuhConfig, WazuhToolLayer


def investigated_alert_ids(artifact_dir: str | Path) -> set[str]:
    """Read alert IDs from local artifacts, ignoring incomplete JSON files."""
    known: set[str] = set()
    directory = Path(artifact_dir)
    if not directory.exists():
        return known
    for path in directory.rglob("*.json"):
        try:
            artifact = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(artifact, Mapping):
            continue
        case = _mapping(artifact.get("case"))
        evidence = case.get("evidence") if isinstance(case.get("evidence"), list) else []
        seed_record = _mapping(_mapping(evidence[0]).get("record")) if evidence else {}
        seed_event = _mapping(seed_record.get("event"))
        candidates = (
            _mapping(_mapping(artifact.get("evidence_packet")).get("alert")).get("alert_id"),
            _mapping(artifact.get("normalized_alert")).get("alert_id"),
            artifact.get("alert_id"),
            case.get("seed_alert_id"),
            seed_record.get("wazuh_alert_id"),
            seed_event.get("id"),
        )
        known.update(str(value) for value in candidates if isinstance(value, str) and value)
    return known


def select_unseen_alert(
    tools: Any,
    known_ids: Iterable[str],
    *,
    minimum_severity: int = 3,
    maximum_severity: int = 16,
    per_severity_limit: int = 25,
    seed: int | None = None,
    scope: AlertScope | None = None,
) -> dict[str, Any]:
    """Return one random unseen alert summary from the controlled tool layer."""
    if not isinstance(minimum_severity, int) or not isinstance(maximum_severity, int) or not 0 <= minimum_severity <= maximum_severity <= 16:
        raise ValueError("severity range must be integers from 0 to 16")
    if not isinstance(per_severity_limit, int) or not 1 <= per_severity_limit <= 100:
        raise ValueError("per_severity_limit must be an integer from 1 to 100")
    known = {item for item in known_ids if isinstance(item, str) and item}
    candidates: dict[str, Mapping[str, Any]] = {}
    failures: list[str] = []
    excluded = 0
    for severity in range(minimum_severity, maximum_severity + 1):
        result = tools.get_alerts(severity, limit=per_severity_limit)
        if not isinstance(result, Mapping) or not result.get("ok"):
            failures.append(f"severity {severity} could not be queried")
            continue
        for alert in result.get("data", []):
            if not isinstance(alert, Mapping):
                continue
            alert_id = alert.get("wazuh_alert_id") or alert.get("alert_id")
            if isinstance(alert_id, str) and alert_id and alert_id not in known:
                if scope is not None and scope.exclusion_reasons(normalize_alert(alert)):
                    excluded += 1
                    continue
                candidates.setdefault(alert_id, alert)
    if not candidates:
        return {"ok": False, "message": "no unseen alert was found in the selected severity range after scope filtering", "known_alert_count": len(known), "excluded_by_scope": excluded, "query_failures": failures}
    selection = random.Random(seed).choice(list(candidates.values()))
    rule = _mapping(selection.get("rule"))
    return {
        "ok": True,
        "alert_id": selection.get("wazuh_alert_id") or selection.get("alert_id"),
        "timestamp": selection.get("timestamp"),
        "host": selection.get("host"),
        "severity": rule.get("level"),
        "rule_id": rule.get("id"),
        "title": rule.get("description"),
        "known_alert_count": len(known),
        "candidate_count": len(candidates),
        "excluded_by_scope": excluded,
        "query_failures": failures,
    }


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Select one locally unseen Wazuh alert without calling an LLM")
    parser.add_argument("--artifact-dir", default="data", help="Local artifact root used to exclude previously investigated alerts")
    parser.add_argument("--min-severity", type=int, default=3)
    parser.add_argument("--max-severity", type=int, default=16)
    parser.add_argument("--per-severity-limit", type=int, default=25)
    parser.add_argument("--seed", type=int, help="Optional reproducible random-selection seed")
    parser.add_argument("--scope-config", default="config/alert_scope.json", help="Project intake scope; does not alter Wazuh")
    args = parser.parse_args()
    try:
        result = select_unseen_alert(
            WazuhToolLayer(WazuhConfig.from_env()), investigated_alert_ids(args.artifact_dir),
            minimum_severity=args.min_severity, maximum_severity=args.max_severity,
            per_severity_limit=args.per_severity_limit, seed=args.seed,
            scope=AlertScope.from_path(args.scope_config),
        )
    except (ValueError, OSError) as exc:
        print(json.dumps({"ok": False, "message": str(exc)}))
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
