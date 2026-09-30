"""Manifest-driven offline benchmark for generic-investigation artifacts.

The benchmark separates *contract quality* (traceability and safe handling)
from *analyst judgment accuracy*.  The latter is only measured for cases with
an independently recorded expected assessment, never inferred from a model's
own report.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

try:
    from .generic_evaluation import evaluate_generic_artifact
except ImportError:
    from generic_evaluation import evaluate_generic_artifact


VALID_EXPECTATIONS = {"accepted", "accepted_with_flags", "safe_rejection"}


def run_generic_benchmark(manifest_path: str | Path) -> dict[str, Any]:
    manifest_file = Path(manifest_path)
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    cases = manifest.get("cases") if isinstance(manifest, Mapping) else None
    if not isinstance(cases, list) or not cases:
        raise ValueError("benchmark manifest requires a non-empty cases list")
    results = []
    for case in cases:
        if not isinstance(case, Mapping):
            raise ValueError("benchmark case must be an object")
        case_id = case.get("id")
        artifact = case.get("artifact")
        expected = case.get("expected_outcome")
        if not isinstance(case_id, str) or not isinstance(artifact, str) or expected not in VALID_EXPECTATIONS:
            raise ValueError("benchmark case requires id, artifact, and a valid expected_outcome")
        outcome = evaluate_generic_artifact(manifest_file.parent.parent / artifact)
        outcome["benchmark_id"] = case_id
        outcome["category"] = case.get("category", "unspecified")
        outcome["expected_outcome"] = expected
        outcome["expectation_met"] = outcome["outcome"] == expected
        if not outcome["expectation_met"]:
            outcome["issues"].append(f"expected benchmark outcome {expected!r}, got {outcome['outcome']!r}")
            outcome["passed"] = False
        results.append(outcome)
    contract_passed = all(item["passed"] and item["expectation_met"] for item in results)
    truth_labeled = [item for item in cases if isinstance(item, Mapping) and item.get("independent_truth_label") is not None]
    return {
        "benchmark": manifest.get("name", manifest_file.stem) if isinstance(manifest, Mapping) else manifest_file.stem,
        "cases": len(results), "contract_gate_passed": contract_passed,
        "independently_truth_labeled_cases": len(truth_labeled),
        "analyst_accuracy_measured": bool(truth_labeled),
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an offline generic-investigation benchmark manifest")
    parser.add_argument("--manifest", default="benchmarks/generic_v1_contract_manifest.json")
    args = parser.parse_args()
    result = run_generic_benchmark(args.manifest)
    print(json.dumps(result, indent=2))
    return 0 if result["contract_gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
