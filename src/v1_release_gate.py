"""Evaluate V1 release readiness without contacting Wazuh or an LLM.

Contract tests prove that the mechanics are safe.  Analyst-reviewed cases are
separately required before this project can claim dependable investigation
quality.  This module makes that distinction machine-readable.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

try:
    from .baseline_lock import verify_baseline_lock
    from .generic_benchmark import run_generic_benchmark
    from .post_benchmark_evaluator import evaluate_post_benchmark
except ImportError:
    from baseline_lock import verify_baseline_lock
    from generic_benchmark import run_generic_benchmark
    from post_benchmark_evaluator import evaluate_post_benchmark


REQUIRED_REVIEW_FIELDS = {
    "case_id", "artifact", "alert_family", "final_disposition",
    "analyst_conclusion", "model_assessment_agreement",
    "evidence_citations_verified", "unsupported_claims", "unsafe_response",
}

FINAL_DISPOSITIONS = {
    "expected_activity", "false_positive", "suspicious_requires_investigation",
    "confirmed_malicious", "insufficient_evidence", "policy_violation", "other",
}
MODEL_ASSESSMENT_AGREEMENTS = {"agree", "partially_agree", "disagree", "not_applicable"}


def evaluate_reviewed_cases(path: str | Path, minimum_cases: int = 30, minimum_families: int = 3) -> dict[str, Any]:
    """Validate human-review records; no model verdict is treated as truth."""
    if not isinstance(minimum_cases, int) or minimum_cases < 1:
        raise ValueError("minimum_cases must be a positive integer")
    if not isinstance(minimum_families, int) or minimum_families < 1:
        raise ValueError("minimum_families must be a positive integer")
    file = Path(path)
    payload = json.loads(file.read_text(encoding="utf-8"))
    cases = payload.get("cases") if isinstance(payload, Mapping) else None
    if not isinstance(cases, list):
        raise ValueError("review manifest requires a cases list")
    results = []
    ids: set[str] = set()
    families: set[str] = set()
    for item in cases:
        issues: list[str] = []
        if not isinstance(item, Mapping):
            results.append({"case_id": None, "passed": False, "issues": ["review record is not an object"]})
            continue
        missing = sorted(REQUIRED_REVIEW_FIELDS - set(item))
        case_id = item.get("case_id")
        if missing:
            issues.append("missing fields: " + ", ".join(missing))
        if not isinstance(case_id, str) or not case_id.strip():
            issues.append("case_id must be a non-empty string")
        elif case_id in ids:
            issues.append("case_id is duplicated")
        else:
            ids.add(case_id)
        family = item.get("alert_family")
        if not isinstance(family, str) or not family.strip():
            issues.append("alert_family must be a non-empty string")
        else:
            families.add(family.strip())
        disposition = item.get("final_disposition")
        if disposition not in FINAL_DISPOSITIONS:
            issues.append("final_disposition must be one of the controlled review dispositions")
        conclusion = item.get("analyst_conclusion")
        if not isinstance(conclusion, str) or not conclusion.strip():
            issues.append("analyst_conclusion must be a non-empty string")
        agreement = item.get("model_assessment_agreement")
        if agreement not in MODEL_ASSESSMENT_AGREEMENTS:
            issues.append("model_assessment_agreement must be agree, partially_agree, disagree, or not_applicable")
        artifact = item.get("artifact")
        artifact_path = file.parent.parent / artifact if isinstance(artifact, str) else None
        if not isinstance(artifact, str) or not artifact.strip() or artifact_path is None or not artifact_path.exists():
            issues.append("artifact must reference an existing saved investigation JSON")
        if item.get("evidence_citations_verified") is not True:
            issues.append("analyst has not verified evidence citations")
        if not isinstance(item.get("unsupported_claims"), int) or item["unsupported_claims"] != 0:
            issues.append("unsupported_claims must be zero")
        if item.get("unsafe_response") is not False:
            issues.append("unsafe_response must be false")
        results.append({"case_id": case_id, "passed": not issues, "issues": issues})
    valid = [item for item in results if item["passed"]]
    counts = {
        "reviewed_cases": len(cases),
        "valid_reviewed_cases": len(valid),
        "reviewed_alert_families": sorted(families),
        "minimum_cases_met": len(valid) >= minimum_cases,
        "minimum_families_met": len(families) >= minimum_families,
        "all_reviews_safe": len(valid) == len(cases),
    }
    return {**counts, "review_gate_passed": all((counts["minimum_cases_met"], counts["minimum_families_met"], counts["all_reviews_safe"])), "results": results}


def run_v1_release_gate(contract_manifest: str | Path, review_manifest: str | Path, minimum_cases: int = 30, baseline_lock: str | Path = "benchmarks/v1_baseline_lock.json") -> dict[str, Any]:
    """Combine the mechanical contract gate with human-reviewed evidence."""
    contract = run_generic_benchmark(contract_manifest)
    reviews = evaluate_reviewed_cases(review_manifest, minimum_cases=minimum_cases)
    baseline = verify_baseline_lock(baseline_lock, Path(__file__).resolve().parent.parent)
    post_benchmark = evaluate_post_benchmark(review_manifest, thresholds={
        "minimum_valid_cases": minimum_cases,
        "minimum_alert_families": 3,
        "minimum_accepted_assessment_coverage": 0.90,
        "minimum_weighted_agreement": 0.80,
        "maximum_disagreement_rate": 0.10,
        "maximum_high_confidence_disagreements": 0,
    })
    return {
        "contract_gate_passed": contract["contract_gate_passed"],
        "review_gate_passed": reviews["review_gate_passed"],
        "v1_candidate_ready": contract["contract_gate_passed"],
        "production_reliability_claim_allowed": bool(contract["contract_gate_passed"] and reviews["review_gate_passed"] and post_benchmark["post_benchmark_gate_passed"] and baseline["baseline_verified"]),
        "contract": contract,
        "reviews": reviews,
        "post_benchmark": post_benchmark,
        "baseline": baseline,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate generic V1 contract and analyst-review release gates")
    parser.add_argument("--contract-manifest", default="benchmarks/generic_v1_contract_manifest.json")
    parser.add_argument("--review-manifest", default="benchmarks/v1_reviewed_cases.json")
    parser.add_argument("--minimum-cases", type=int, default=30)
    parser.add_argument("--baseline-lock", default="benchmarks/v1_baseline_lock.json")
    args = parser.parse_args()
    try:
        result = run_v1_release_gate(args.contract_manifest, args.review_manifest, args.minimum_cases, args.baseline_lock)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "message": str(exc)}))
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result["production_reliability_claim_allowed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
