"""Deterministic correlation primitives used before LLM interpretation."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Mapping

try:
    from .case_models import InvestigationCase
except ImportError:
    from case_models import InvestigationCase


@dataclass
class ProcessNode:
    process_guid: str
    image: str | None
    command_line: str | None
    user: str | None
    parent_process_guid: str | None
    evidence_ids: list[str] = field(default_factory=list)
    child_process_guids: list[str] = field(default_factory=list)


@dataclass
class ProcessTree:
    nodes: dict[str, ProcessNode]
    roots: list[str]
    unresolved_parent_guids: list[str]


@dataclass(frozen=True)
class AuthenticationWindow:
    user: str | None
    source_ip: str | None
    target: str | None
    authentication_type: str | None
    start: str | None
    end: str | None
    failures: int
    successes: int
    evidence_ids: list[str]


def attach_deterministic_correlations(case: InvestigationCase) -> InvestigationCase:
    """Persist reproducible correlation output for the model, report, and audit trail."""
    tree = build_process_tree(case)
    prior = dict(case.correlations)
    case.correlations = {
        "process_tree": {
            "nodes": {guid: asdict(node) for guid, node in tree.nodes.items()},
            "roots": tree.roots,
            "unresolved_parent_guids": tree.unresolved_parent_guids,
        },
        "authentication_windows": [asdict(window) for window in correlate_authentication_windows(case)],
        "sysmon_relationships": build_sysmon_relationships(case, tree),
        "telemetry_profiles": prior.get("telemetry_profiles", []),
        "contextual_evidence_ids": sorted(case.contextual_evidence_ids),
    }
    return case


def build_sysmon_relationships(case: InvestigationCase, tree: ProcessTree | None = None) -> list[dict[str, Any]]:
    """Normalize exact, same-endpoint Sysmon links without judging intent.

    Every row originates from an event-specific GUID field.  Object names such
    as registry paths and files are reported as affected objects, never used as
    a causal link by themselves.
    """
    nodes = (tree or build_process_tree(case)).nodes
    seed_fields = _windows_fields(case.evidence[0].record) if case.evidence else {}
    seed_guid = _text(seed_fields.get("processGuid"))
    rows: list[dict[str, Any]] = []
    for evidence in case.evidence:
        if evidence.evidence_id in case.contextual_evidence_ids:
            continue
        fields, event_id = _windows_fields(evidence.record), str(_path(evidence.record, "event", "data", "win", "system", "eventID") or "")
        if event_id in {"3", "7", "11", "12", "13", "14", "22"}:
            guid = _text(fields.get("processGuid"))
            if not guid:
                continue
            node = nodes.get(guid)
            same_seed_process = bool(seed_guid and guid == seed_guid)
            # A matching ProcessGuid is already an exact Sysmon correlation.
            # The absent Event ID 1 record only limits parent/start context; it
            # must not erase the observed same-process relationship.
            status = (
                "same_seed_process" if same_seed_process
                else "process_creation_observed" if node
                else "process_creation_unavailable"
            )
            row = {
                "evidence_id": evidence.evidence_id, "event_id": event_id,
                "relationship": "actor_process", "process_guid": guid,
                "process_image": node.image if node else _text(fields.get("image")),
                "actor_evidence_ids": list(node.evidence_ids) if node else [],
                "same_seed_process": same_seed_process,
                "process_creation_status": "observed" if node else "unavailable",
                "status": status,
            }
            if event_id == "3":
                row["affected_object"] = fields.get("destinationIp")
            elif event_id == "7":
                row["affected_object"] = fields.get("imageLoaded")
            elif event_id == "11":
                row["affected_object"] = fields.get("targetFilename")
            elif event_id in {"12", "13", "14"}:
                row["affected_object"] = fields.get("targetObject")
            elif event_id == "22":
                row["affected_object"] = fields.get("queryName")
            rows.append(row)
        elif event_id == "10":
            source = _text(fields.get("sourceProcessGuid") or fields.get("sourceProcessGUID"))
            target = _text(fields.get("targetProcessGuid") or fields.get("targetProcessGUID"))
            if not source or not target:
                continue
            source_node, target_node = nodes.get(source), nodes.get(target)
            source_same_seed = bool(seed_guid and source == seed_guid)
            source_status = (
                "same_seed_process" if source_same_seed
                else "process_creation_observed" if source_node
                else "process_creation_unavailable"
            )
            target_status = "process_creation_observed" if target_node else "process_creation_unavailable"
            rows.append({
                "evidence_id": evidence.evidence_id, "event_id": event_id, "relationship": "process_access",
                "source_process_guid": source, "target_process_guid": target,
                "source_process_image": source_node.image if source_node else _text(fields.get("sourceImage")),
                "target_process_image": target_node.image if target_node else _text(fields.get("targetImage")),
                "source_evidence_ids": list(source_node.evidence_ids) if source_node else [],
                "target_evidence_ids": list(target_node.evidence_ids) if target_node else [],
                "source_relationship": source_status,
                "target_relationship": target_status,
                "granted_access": fields.get("grantedAccess"),
                "status": "resolved" if source_node and target_node else source_status,
            })
    return rows


def build_process_tree(case: InvestigationCase) -> ProcessTree:
    """Link process events only through observed GUID relationships."""
    nodes: dict[str, ProcessNode] = {}
    for evidence in case.evidence:
        if evidence.evidence_id in case.contextual_evidence_ids:
            continue
        if evidence.event_type != "process_creation":
            continue
        fields = _windows_fields(evidence.record)
        guid = _text(fields.get("processGuid"))
        if not guid:
            continue
        node = nodes.get(guid)
        if node is None:
            node = ProcessNode(
                process_guid=guid,
                image=_text(fields.get("image")),
                command_line=_text(fields.get("commandLine")),
                user=_text(fields.get("user")),
                parent_process_guid=_text(fields.get("parentProcessGuid")),
            )
            nodes[guid] = node
        if evidence.evidence_id not in node.evidence_ids:
            node.evidence_ids.append(evidence.evidence_id)

    unresolved: set[str] = set()
    for node in nodes.values():
        if not node.parent_process_guid:
            continue
        parent = nodes.get(node.parent_process_guid)
        if parent is None:
            unresolved.add(node.parent_process_guid)
        elif node.process_guid not in parent.child_process_guids:
            parent.child_process_guids.append(node.process_guid)
    roots = sorted(guid for guid, node in nodes.items() if not node.parent_process_guid or node.parent_process_guid not in nodes)
    return ProcessTree(nodes=nodes, roots=roots, unresolved_parent_guids=sorted(unresolved))


def correlate_authentication_windows(case: InvestigationCase, max_gap_seconds: int = 300) -> list[AuthenticationWindow]:
    """Group authentication events by identity/source/target within bounded gaps."""
    observations: list[tuple[tuple[str | None, ...], datetime | None, str | None, str]] = []
    for evidence in case.evidence:
        fields = _windows_fields(evidence.record)
        rule = evidence.record.get("rule", {})
        groups = rule.get("groups", []) if isinstance(rule, Mapping) else []
        if evidence.event_type != "authentication" and not any("authentication" in str(group).lower() for group in groups):
            continue
        key = (
            _text(fields.get("targetUserName") or fields.get("user")),
            _text(fields.get("ipAddress") or fields.get("sourceIp") or _path(evidence.record, "event", "source", "ip")),
            _text(fields.get("workstationName") or fields.get("targetServerName") or evidence.record.get("host")),
            _text(fields.get("logonType") or fields.get("authenticationPackageName")),
        )
        observations.append((key, _parse_time(evidence.timestamp), _auth_outcome(evidence.record), evidence.evidence_id))

    grouped: dict[tuple[str | None, ...], list[tuple[datetime | None, str | None, str]]] = {}
    for key, timestamp, outcome, evidence_id in observations:
        grouped.setdefault(key, []).append((timestamp, outcome, evidence_id))

    windows: list[AuthenticationWindow] = []
    for key, values in grouped.items():
        values.sort(key=lambda value: value[0] or datetime.min)
        current: list[tuple[datetime | None, str | None, str]] = []
        for value in values:
            if current and value[0] and current[-1][0] and (value[0] - current[-1][0]).total_seconds() > max_gap_seconds:
                windows.append(_make_window(key, current))
                current = []
            current.append(value)
        if current:
            windows.append(_make_window(key, current))
    return windows


def _make_window(key: tuple[str | None, ...], values: list[tuple[datetime | None, str | None, str]]) -> AuthenticationWindow:
    start, end = values[0][0], values[-1][0]
    return AuthenticationWindow(
        user=key[0], source_ip=key[1], target=key[2], authentication_type=key[3],
        start=start.isoformat().replace("+00:00", "Z") if start else None,
        end=end.isoformat().replace("+00:00", "Z") if end else None,
        failures=sum(value[1] == "failure" for value in values),
        successes=sum(value[1] == "success" for value in values),
        evidence_ids=[value[2] for value in values],
    )


def _auth_outcome(alert: Mapping[str, Any]) -> str | None:
    rule = alert.get("rule", {})
    description = rule.get("description", "") if isinstance(rule, Mapping) else ""
    text = str(description).lower()
    if any(token in text for token in ("failed", "failure", "invalid", "denied")):
        return "failure"
    if any(token in text for token in ("successful", "success", "logged on")):
        return "success"
    return None


def _windows_fields(alert: Mapping[str, Any]) -> Mapping[str, Any]:
    return _path(alert, "event", "data", "win", "eventdata") or {}


def _path(value: Any, *path: str) -> Any:
    current: Any = value
    for component in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(component)
    return current


def _text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
