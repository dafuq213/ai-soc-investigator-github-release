"""Offline quality gate for generic investigation artifacts.

This evaluates what was already collected and what a model already returned.
It never contacts Wazuh or an LLM.  The gate is intentionally alert-family
neutral: it checks evidence provenance, citations, assessment parsing, and
report rendering rather than expecting a separate benchmark for every rule.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Mapping

try:
    from .generic_assessment import parse_generic_assessment
except ImportError:
    from generic_assessment import parse_generic_assessment


MAX_EVIDENCE_ITEMS = 13
ACCEPTED_HEADINGS = (
    "## Case metadata", "## Executive summary", "## Alert overview", "## Evidence timeline",
    "## Assessment", "### What happened", "### Alert claim assessment",
    "## Confidence rationale", "### Possible legitimate context", "### Concern factors",
    "## Key gaps and cautions", "### Evidence limitations",
    "## Recommended analyst actions",
)
REJECTED_HEADINGS = ("## Case metadata", "## Executive summary", "## Alert overview", "## Evidence timeline", "## Assessment")
EVIDENCE_REFERENCE = re.compile(r"\[(E\d{2})\]")


def evaluate_generic_artifact(path: str | Path) -> dict[str, Any]:
    """Evaluate one saved ``investigate_generic`` JSON artifact offline."""
    artifact_path = Path(path)
    artifact = _load_json(artifact_path)
    if not isinstance(artifact, Mapping):
        raise ValueError("artifact must be a JSON object")
    packet = _mapping(artifact.get("evidence_packet"))
    report_path = artifact_path.with_suffix(".md")
    report = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
    checks: dict[str, bool] = {}
    issues: list[str] = []

    packet_issues, evidence_ids = _packet_issues(packet)
    checks["packet_integrity"] = not packet_issues
    issues.extend(packet_issues)

    model = _mapping(artifact.get("model_execution"))
    raw_response, response_issue = _saved_response(artifact, artifact_path)
    model_invoked = bool(model.get("invoked"))
    checks["model_response_audited"] = not model_invoked or raw_response is not None
    if response_issue:
        issues.append(response_issue)

    replayed: dict[str, Any] | None = None
    replay_error: str | None = None
    if raw_response is not None and checks["packet_integrity"]:
        try:
            replayed = parse_generic_assessment(raw_response, packet)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            replay_error = str(exc)

    stored = artifact.get("assessment")
    if replayed is not None:
        checks["assessment_contract"] = True
        expected_status = replayed["assessment_status"]
        if not isinstance(stored, Mapping):
            checks["assessment_policy_current"] = False
            issues.append("saved artifact withholds an assessment that now passes the current contract")
        else:
            checks["assessment_policy_current"] = (
                stored.get("assessment_status", "accepted") == expected_status
                and stored.get("verdict") == replayed.get("verdict")
                and stored.get("confidence") == replayed.get("confidence")
            )
            if not checks["assessment_policy_current"]:
                issues.append("saved assessment differs from current contract replay")
    elif raw_response is not None:
        # The response did *not* pass the contract, but the gate itself did
        # its job when the invalid response was withheld.  Keep this control
        # true and expose the rejected model output through ``safe_rejection``
        # rather than incorrectly failing the safety mechanism.
        checks["assessment_contract"] = stored is None
        checks["assessment_policy_current"] = stored is None
        issues.append("saved model response is invalid under the current contract: " + _text(replay_error))
    else:
        checks["assessment_contract"] = not model_invoked
        checks["assessment_policy_current"] = stored is None

    accepted = replayed is not None
    required_headings = ACCEPTED_HEADINGS if accepted else REJECTED_HEADINGS
    checks["report_structure"] = bool(report) and all(heading in report for heading in required_headings)
    if not checks["report_structure"]:
        issues.append("report is missing required headings for its assessment state")
    report_refs = set(EVIDENCE_REFERENCE.findall(report))
    checks["report_citations_traceable"] = report_refs.issubset(evidence_ids)
    if not checks["report_citations_traceable"]:
        issues.append("report cites evidence IDs absent from the packet")

    if accepted:
        checks["report_status_current"] = f"Assessment status: **{replayed['assessment_status']}**" in report
        if not checks["report_status_current"]:
            issues.append("report assessment status does not match current contract replay")
        flags = replayed.get("quality_flags", [])
        checks["flags_rendered"] = all(
            isinstance(flag, Mapping) and (
                _text(flag.get("message")) in report
                or _text(flag.get("code")).replace("_", " ").title() in report
            ) for flag in flags
        )
        if not checks["flags_rendered"]:
            issues.append("report does not render every current assessment caution")
    else:
        checks["report_status_current"] = "No accepted model assessment is available." in report
        checks["flags_rendered"] = True

    # A correctly withheld malformed response is a safe outcome, not a model
    # success.  It is reported separately so release metrics cannot confuse it
    # with high-quality accepted reasoning.
    safe_rejection = raw_response is not None and replayed is None and stored is None and checks["report_status_current"]
    passed = all(checks.values())
    outcome = (
        "accepted" if passed and accepted and not replayed.get("quality_flags") else
        "accepted_with_flags" if passed and accepted else
        "safe_rejection" if passed and safe_rejection else
        "failed"
    )
    score = round(100 * sum(checks.values()) / len(checks)) if checks else 0
    return {
        "artifact": str(artifact_path), "case_id": artifact_path.stem,
        "passed": passed, "outcome": outcome, "quality_score": score,
        "checks": checks, "issues": issues,
        "replayed_assessment_status": replayed.get("assessment_status") if replayed else None,
        "replayed_verdict": replayed.get("verdict") if replayed else None,
        "replay_error": replay_error,
    }


def evaluate_many(paths: list[str | Path]) -> dict[str, Any]:
    """Evaluate multiple artifacts and expose release-facing aggregate metrics."""
    results = [evaluate_generic_artifact(path) for path in paths]
    passed = sum(item["passed"] for item in results)
    accepted = sum(item["outcome"] in {"accepted", "accepted_with_flags"} for item in results)
    return {
        "cases": len(results), "passed": passed, "failed": len(results) - passed,
        "accepted_assessments": accepted,
        "safe_rejections": sum(item["outcome"] == "safe_rejection" for item in results),
        "quality_gate_passed": bool(results) and passed == len(results),
        "results": results,
    }


def _packet_issues(packet: Mapping[str, Any]) -> tuple[list[str], set[str]]:
    issues: list[str] = []
    if packet.get("schema_version") != "evidence_packet_v1":
        issues.append("packet schema version is missing or unsupported")
    alert = _mapping(packet.get("alert"))
    if not _text(alert.get("alert_id")) or not _text(alert.get("title")):
        issues.append("packet alert identity is incomplete")
    evidence = packet.get("evidence")
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= MAX_EVIDENCE_ITEMS:
        return [*issues, "packet evidence count is outside the bounded range"], set()
    ids = {f"E{index:02d}" for index in range(1, len(evidence) + 1)}
    actual_ids = {item.get("id") for item in evidence if isinstance(item, Mapping)}
    if actual_ids != ids:
        issues.append("packet evidence IDs are not contiguous E01…En")
    for item in evidence:
        if not isinstance(item, Mapping) or not _text(item.get("summary")) or not isinstance(item.get("fields"), Mapping):
            issues.append("packet contains an incomplete evidence item")
            break
        source = _mapping(item.get("source"))
        if not _text(source.get("alert_id")) and not _text(source.get("document_id")):
            issues.append("packet evidence lacks a source reference")
            break
    return issues, ids


def _saved_response(artifact: Mapping[str, Any], artifact_path: Path) -> tuple[str | None, str | None]:
    audit = _mapping(artifact.get("prompt_audit"))
    response_path = audit.get("response_path")
    if not isinstance(response_path, str) or not response_path:
        return None, "model was invoked but no response audit path is recorded" if _mapping(artifact.get("model_execution")).get("invoked") else None
    candidate = Path(response_path)
    if not candidate.is_absolute():
        candidate = artifact_path.parent / candidate
    if not candidate.exists():
        return None, "saved response audit is missing"
    data = _load_json(candidate)
    response = data.get("response") if isinstance(data, Mapping) else None
    return (response, None) if isinstance(response, str) else (None, "saved response audit has no response text")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: Any) -> str:
    return str(value) if value not in (None, "") else ""


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate saved generic-investigation artifacts without calling an LLM")
    parser.add_argument("--case", action="append", required=True, help="Path to one saved GENERIC-*.json artifact; repeat for multiple cases")
    args = parser.parse_args()
    result = evaluate_many(args.case)
    print(json.dumps(result, indent=2))
    return 0 if result["quality_gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
