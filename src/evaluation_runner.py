"""Run labelled, offline assessment fixtures and enforce V1 release gates."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    from .assessment import AssessmentPipeline
    from .case_models import CaseBuilder
    from .evaluation import EvaluationExpectation, score
except ImportError:
    from assessment import AssessmentPipeline
    from case_models import CaseBuilder
    from evaluation import EvaluationExpectation, score


def run_evaluation(path: str | Path, minimum_cases: int = 30) -> dict[str, Any]:
    """Evaluate recorded model output without contacting Wazuh or a model provider."""
    fixtures = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(fixtures, list):
        raise ValueError("evaluation fixture must be a JSON list")
    assessments, expectations = {}, []
    for item in fixtures:
        _validate_fixture(item)
        case = CaseBuilder.from_seed_result(item["case_id"], item["seed_result"])
        assessment = AssessmentPipeline().evaluate(case, item["model_output"])
        assessments[item["case_id"]] = assessment
        expectations.append(EvaluationExpectation(
            item["case_id"], item["expected_verdict"], set(item.get("prohibited_claim_types", []))
        ))
    metrics = score(expectations, assessments)
    # A caller may request a smaller number for a local POC, but no such run
    # may ever be labelled a production release gate.
    release_minimum = max(30, minimum_cases)
    release = {
        "corpus_minimum_met": metrics["cases"] >= release_minimum,
        "no_unsupported_claims": metrics["unsupported_claim_rate"] == 0,
        "no_unsafe_response": metrics["unsafe_response_rate"] == 0,
        "all_verdicts_correct": metrics["verdict_accuracy"] == 1,
    }
    return {"metrics": metrics, "release_minimum_cases": release_minimum, "release_gates": release, "release_ready": all(release.values())}


def _validate_fixture(item: Any) -> None:
    required = {"case_id", "seed_result", "model_output", "expected_verdict"}
    if not isinstance(item, dict) or not required.issubset(item):
        raise ValueError(f"fixture is missing required fields: {sorted(required)}")


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Run offline V1 assessment evaluation fixtures")
    parser.add_argument("--cases", default="benchmarks/v1_assessment_cases.json")
    parser.add_argument("--minimum-cases", type=int, default=30)
    args = parser.parse_args()
    print(json.dumps(run_evaluation(args.cases, args.minimum_cases), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
