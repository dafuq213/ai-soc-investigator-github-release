"""Create and record human review of saved generic investigations.

This module deliberately does not grade an investigation or infer an analyst
verdict.  Its purpose is to make the human evidence check behind the V1 release
gate repeatable and auditable without another Wazuh or LLM request.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping


REQUIRED_REVIEW_VALUES = {
    "case_id", "artifact", "alert_family", "final_disposition",
    "analyst_conclusion", "model_assessment_agreement",
    "evidence_citations_verified", "unsupported_claims", "unsafe_response",
}

FINAL_DISPOSITIONS = (
    "expected_activity", "false_positive", "suspicious_requires_investigation",
    "confirmed_malicious", "insufficient_evidence", "policy_violation", "other",
)
MODEL_ASSESSMENT_AGREEMENTS = ("agree", "partially_agree", "disagree", "not_applicable")


def load_investigation(path: str | Path) -> dict[str, Any]:
    """Load a saved generic investigation and reject incomplete artifacts."""
    file = Path(path)
    payload = json.loads(file.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping) or not isinstance(payload.get("evidence_packet"), Mapping):
        raise ValueError("artifact must be a generic investigation JSON with evidence_packet")
    return dict(payload)


def build_review_worksheet(artifact_path: str | Path) -> str:
    """Render a compact worksheet containing observed facts, never a new judgment."""
    file = Path(artifact_path)
    artifact = load_investigation(file)
    packet = _mapping(artifact.get("evidence_packet"))
    alert = _mapping(packet.get("alert"))
    assessment = _mapping(artifact.get("assessment"))
    model = _mapping(artifact.get("model_execution"))
    case_id = file.stem
    lines = [
        f"# Analyst review — {case_id}", "",
        "Complete this worksheet after inspecting the bounded evidence and the saved report.",
        "Do not treat a model conclusion as a ground-truth label.", "",
        "## Case", "",
        f"- Case ID: `{case_id}`",
        f"- Artifact: `{file.as_posix()}`",
        f"- Alert ID: `{_text(alert.get('alert_id'), 'not recorded')}`",
        f"- Alert name: {_text(alert.get('title'), 'not recorded')}",
        f"- Timestamp (UTC): `{_text(alert.get('timestamp_utc'), 'not recorded')}`",
        f"- Severity: `{_text(alert.get('severity'), 'not recorded')}`",
        f"- Source: `{_source_text(_mapping(alert.get('source')))}`", "",
        "## Observed evidence", "",
    ]
    evidence = packet.get("evidence")
    if isinstance(evidence, list):
        for item in evidence:
            if not isinstance(item, Mapping):
                continue
            fields = _mapping(item.get("fields"))
            details = _field_summary(fields)
            suffix = f" — {details}" if details else ""
            lines.append(f"- **{_text(item.get('id'), 'E??')}** {_text(item.get('summary'), 'Observed event.')}{suffix}")
    if not isinstance(evidence, list) or not evidence:
        lines.append("- No bounded evidence records were saved.")
    lines.extend(["", "## Saved model assessment", ""])
    if assessment:
        lines.extend([
            f"- Model: `{_text(model.get('provider'), 'not recorded')} / {_text(model.get('model'), 'not recorded')}`",
            f"- Status: `{_text(assessment.get('assessment_status'), 'not recorded')}`",
            f"- Verdict: `{_text(assessment.get('verdict'), 'not recorded')}`",
            f"- Confidence: `{_text(assessment.get('confidence'), 'not recorded')}/100`",
        ])
    else:
        lines.append("- No accepted model assessment was saved.")
    lines.extend([
        "", "## Analyst review record", "",
        "Complete this single record. `analyst_conclusion` is free text; it can document",
        "business knowledge, disagreement with the model, and follow-up context.",
        "`final_disposition` must be one of: " + ", ".join(FINAL_DISPOSITIONS) + ".",
        "`model_assessment_agreement` must be one of: " + ", ".join(MODEL_ASSESSMENT_AGREEMENTS) + ".",
        "```json",
        json.dumps({
            "case_id": case_id,
            "artifact": _manifest_artifact_path(file),
            "alert_family": "",
            "final_disposition": "",
            "analyst_conclusion": "",
            "model_assessment_agreement": "",
            "evidence_citations_verified": None,
            "unsupported_claims": None,
            "unsafe_response": None,
        }, indent=2),
        "```", "",
    ])
    return "\n".join(lines)


def append_review_record(
    manifest_path: str | Path,
    artifact_path: str | Path,
    *,
    alert_family: str,
    final_disposition: str,
    analyst_conclusion: str,
    model_assessment_agreement: str,
    evidence_citations_verified: bool,
    unsupported_claims: int,
    unsafe_response: bool,
) -> dict[str, Any]:
    """Append one explicitly supplied human review record to the manifest."""
    artifact = Path(artifact_path)
    load_investigation(artifact)
    if not alert_family.strip() or not analyst_conclusion.strip():
        raise ValueError("alert_family and analyst_conclusion must be non-empty")
    if final_disposition not in FINAL_DISPOSITIONS:
        raise ValueError("final_disposition is not a supported review disposition")
    if model_assessment_agreement not in MODEL_ASSESSMENT_AGREEMENTS:
        raise ValueError("model_assessment_agreement is not a supported agreement value")
    if not isinstance(unsupported_claims, int) or unsupported_claims < 0:
        raise ValueError("unsupported_claims must be a non-negative integer")
    manifest = Path(manifest_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping) or not isinstance(payload.get("cases"), list):
        raise ValueError("review manifest requires a cases list")
    case_id = artifact.stem
    if any(isinstance(item, Mapping) and item.get("case_id") == case_id for item in payload["cases"]):
        raise ValueError(f"review record already exists for {case_id}")
    record = {
        "case_id": case_id,
        "artifact": _manifest_artifact_path(artifact),
        "alert_family": alert_family.strip(),
        "final_disposition": final_disposition,
        "analyst_conclusion": analyst_conclusion.strip(),
        "model_assessment_agreement": model_assessment_agreement,
        "evidence_citations_verified": evidence_citations_verified,
        "unsupported_claims": unsupported_claims,
        "unsafe_response": unsafe_response,
    }
    payload = dict(payload)
    payload["cases"] = [*payload["cases"], record]
    manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return record


def _manifest_artifact_path(path: Path) -> str:
    """Keep records portable from the repository root when possible."""
    resolved = path.resolve()
    for parent in (Path.cwd().resolve(), *Path.cwd().resolve().parents):
        try:
            return resolved.relative_to(parent).as_posix()
        except ValueError:
            continue
    return resolved.as_posix()


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: Any, fallback: str = "") -> str:
    return str(value) if value not in (None, "") else fallback


def _source_text(source: Mapping[str, Any]) -> str:
    return " / ".join(str(source[key]) for key in ("provider", "channel", "event_id") if source.get(key) not in (None, "")) or "not recorded"


def _field_summary(fields: Mapping[str, Any]) -> str:
    labels = (("host", "host"), ("user", "user"), ("process_name", "process"), ("parent_process_name", "parent"), ("target_process_name", "target"), ("source_ip", "source IP"), ("destination_ip", "destination IP"), ("registry_key", "registry key"), ("file_path", "file"))
    return "; ".join(f"{label}: `{fields[key]}`" for key, label in labels if fields.get(key) not in (None, ""))


def _parse_bool(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    raise argparse.ArgumentTypeError("must be true or false")


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or record an explicit analyst review for a saved investigation")
    parser.add_argument("--artifact", required=True, help="Saved generic investigation JSON")
    parser.add_argument("--output", help="Write a compact Markdown review worksheet")
    parser.add_argument("--append-review", action="store_true", help="Append supplied analyst inputs to a review manifest")
    parser.add_argument("--review-manifest", default="benchmarks/v1_reviewed_cases.json")
    parser.add_argument("--alert-family")
    parser.add_argument("--final-disposition", choices=FINAL_DISPOSITIONS)
    parser.add_argument("--analyst-conclusion")
    parser.add_argument("--model-assessment-agreement", choices=MODEL_ASSESSMENT_AGREEMENTS)
    parser.add_argument("--citations-verified", type=_parse_bool)
    parser.add_argument("--unsupported-claims", type=int)
    parser.add_argument("--unsafe-response", type=_parse_bool)
    args = parser.parse_args()
    try:
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(build_review_worksheet(args.artifact), encoding="utf-8")
        if args.append_review:
            missing = [name for name, value in {
                "--alert-family": args.alert_family,
                "--final-disposition": args.final_disposition,
                "--analyst-conclusion": args.analyst_conclusion,
                "--model-assessment-agreement": args.model_assessment_agreement,
                "--citations-verified": args.citations_verified,
                "--unsupported-claims": args.unsupported_claims,
                "--unsafe-response": args.unsafe_response,
            }.items() if value is None]
            if missing:
                raise ValueError("append-review requires " + ", ".join(missing))
            record = append_review_record(args.review_manifest, args.artifact, alert_family=args.alert_family, final_disposition=args.final_disposition, analyst_conclusion=args.analyst_conclusion, model_assessment_agreement=args.model_assessment_agreement, evidence_citations_verified=args.citations_verified, unsupported_claims=args.unsupported_claims, unsafe_response=args.unsafe_response)
        else:
            record = None
        print(json.dumps({"ok": True, "worksheet": args.output, "review_record": record}, indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "message": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
