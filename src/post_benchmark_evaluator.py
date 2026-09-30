"""Offline outcome metrics for analyst-reviewed generic investigations.

This measures accepted model assessments against explicit human reviews. It
never contacts Wazuh or an LLM and never infers a reviewer decision.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import mean
from typing import Any, Mapping

THRESHOLDS = {
    "minimum_valid_cases": 30,
    "minimum_alert_families": 3,
    "minimum_accepted_assessment_coverage": 0.90,
    "minimum_weighted_agreement": 0.80,
    "maximum_disagreement_rate": 0.10,
    "maximum_high_confidence_disagreements": 0,
}
AGREEMENT_WEIGHT = {"agree": 1.0, "partially_agree": 0.5, "disagree": 0.0}


def evaluate_post_benchmark(path: str | Path, *, thresholds: Mapping[str, Any] = THRESHOLDS) -> dict[str, Any]:
    """Measure review outcomes and apply the explicit V1 release thresholds."""
    # Local import prevents a circular module import when the top-level release
    # gate also includes these outcome metrics.
    try:
        from .v1_release_gate import evaluate_reviewed_cases
    except ImportError:
        from v1_release_gate import evaluate_reviewed_cases
    manifest_file = Path(path)
    payload = json.loads(manifest_file.read_text(encoding="utf-8"))
    cases = payload.get("cases") if isinstance(payload, Mapping) else None
    if not isinstance(cases, list):
        raise ValueError("review manifest requires a cases list")
    review_gate = evaluate_reviewed_cases(manifest_file, minimum_cases=int(thresholds["minimum_valid_cases"]), minimum_families=int(thresholds["minimum_alert_families"]))
    valid_ids = {item["case_id"] for item in review_gate["results"] if item["passed"]}
    rows: list[dict[str, Any]] = []
    for record in cases:
        if not isinstance(record, Mapping) or record.get("case_id") not in valid_ids:
            continue
        artifact_path = manifest_file.parent.parent / str(record["artifact"])
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        model, assessment = _mapping(artifact.get("model_execution")), _mapping(artifact.get("assessment"))
        accepted = bool(model.get("invoked")) and bool(assessment) and isinstance(assessment.get("confidence"), int)
        rows.append({"case_id": record["case_id"], "alert_family": record["alert_family"], "final_disposition": record["final_disposition"], "agreement": record["model_assessment_agreement"], "model_invoked": bool(model.get("invoked")), "accepted_assessment": accepted, "model_verdict": assessment.get("verdict") if accepted else None, "model_confidence": assessment.get("confidence") if accepted else None})
    assessed = [row for row in rows if row["accepted_assessment"]]
    agreement_rows = [row for row in assessed if row["agreement"] in AGREEMENT_WEIGHT]
    weights = [AGREEMENT_WEIGHT[row["agreement"]] for row in agreement_rows]
    disagreements = [row for row in agreement_rows if row["agreement"] == "disagree"]
    high_confidence_disagreements = [row for row in disagreements if row["model_confidence"] >= 70]
    agree_confidences = [row["model_confidence"] for row in agreement_rows if row["agreement"] == "agree"]
    disagree_confidences = [row["model_confidence"] for row in disagreements]
    coverage = len(assessed) / len(rows) if rows else 0.0
    weighted_agreement = sum(weights) / len(weights) if weights else 0.0
    disagreement_rate = len(disagreements) / len(agreement_rows) if agreement_rows else 1.0
    calibration = {"evaluable": len(agree_confidences) >= 3 and len(disagree_confidences) >= 3, "mean_confidence_when_agreed": round(mean(agree_confidences), 2) if agree_confidences else None, "mean_confidence_when_disagreed": round(mean(disagree_confidences), 2) if disagree_confidences else None, "confidence_separation": round(mean(agree_confidences) - mean(disagree_confidences), 2) if agree_confidences and disagree_confidences else None, "note": "Informational only: 30 cases are too few for a standalone calibration claim."}
    checks = {"review_safety_and_coverage": review_gate["review_gate_passed"], "accepted_assessment_coverage": coverage >= float(thresholds["minimum_accepted_assessment_coverage"]), "weighted_analyst_agreement": weighted_agreement >= float(thresholds["minimum_weighted_agreement"]), "disagreement_rate": disagreement_rate <= float(thresholds["maximum_disagreement_rate"]), "no_high_confidence_disagreement": len(high_confidence_disagreements) <= int(thresholds["maximum_high_confidence_disagreements"])}
    return {"thresholds": dict(thresholds), "valid_reviewed_cases": len(rows), "alert_families": sorted({row["alert_family"] for row in rows}), "accepted_assessments": len(assessed), "accepted_assessment_coverage": round(coverage, 4), "agreement_counts": {key: sum(row["agreement"] == key for row in agreement_rows) for key in ("agree", "partially_agree", "disagree")}, "weighted_analyst_agreement": round(weighted_agreement, 4), "disagreement_rate": round(disagreement_rate, 4), "high_confidence_disagreements": [row["case_id"] for row in high_confidence_disagreements], "confidence_alignment": calibration, "checks": checks, "post_benchmark_gate_passed": all(checks.values()), "cases": rows}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate reviewed V1 investigations without contacting Wazuh or an LLM")
    parser.add_argument("--review-manifest", default="benchmarks/v1_reviewed_cases.json")
    args = parser.parse_args()
    try:
        result = evaluate_post_benchmark(args.review_manifest)
    except (OSError, ValueError, json.JSONDecodeError, KeyError) as exc:
        print(json.dumps({"ok": False, "message": str(exc)}))
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result["post_benchmark_gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
