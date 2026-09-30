"""Configuration-driven intake scope for this investigation project.

The scope is a local product decision. It never disables, suppresses, or
modifies a Wazuh rule; excluded alerts remain visible in Wazuh.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True)
class AlertScope:
    excluded_rule_groups: frozenset[str]
    excluded_title_patterns: tuple[re.Pattern[str], ...]
    excluded_rule_ids: frozenset[str]

    @classmethod
    def from_path(cls, path: str | Path) -> "AlertScope":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, Mapping) or payload.get("schema_version") != "alert_scope_v1":
            raise ValueError("scope configuration must use schema_version alert_scope_v1")
        groups = _string_set(payload.get("excluded_rule_groups"), "excluded_rule_groups")
        rule_ids = _string_set(payload.get("excluded_rule_ids"), "excluded_rule_ids")
        patterns = payload.get("excluded_title_patterns")
        if not isinstance(patterns, list) or not all(isinstance(item, str) and item for item in patterns):
            raise ValueError("excluded_title_patterns must be a list of non-empty regular expressions")
        try:
            compiled = tuple(re.compile(item, re.IGNORECASE) for item in patterns)
        except re.error as exc:
            raise ValueError(f"invalid excluded title pattern: {exc}") from exc
        return cls(groups, compiled, rule_ids)

    def exclusion_reasons(self, normalized_alert: Mapping[str, Any]) -> list[str]:
        """Return observed rule metadata that places this alert out of scope."""
        source = normalized_alert.get("source") if isinstance(normalized_alert.get("source"), Mapping) else {}
        groups = source.get("groups") if isinstance(source.get("groups"), list) else []
        reasons = [f"rule group: {group}" for group in groups if isinstance(group, str) and group.casefold() in self.excluded_rule_groups]
        rule_id = normalized_alert.get("rule_id")
        if isinstance(rule_id, str) and rule_id.casefold() in self.excluded_rule_ids:
            reasons.append(f"rule ID: {rule_id}")
        title = normalized_alert.get("title")
        if isinstance(title, str):
            reasons.extend(f"title pattern: {pattern.pattern}" for pattern in self.excluded_title_patterns if pattern.search(title))
        return reasons


def _string_set(value: Any, name: str) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"{name} must be a list of non-empty strings")
    return frozenset(item.strip().casefold() for item in value)
