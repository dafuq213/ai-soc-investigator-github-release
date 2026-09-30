"""Score assessed controlled fixtures against independently known lab facts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping


def evaluate_truth_labels(labels_path: str | Path, corpus_dir: str | Path) -> dict[str, Any]:
    """Evaluate assessed corpus artifacts; evidence-only artifacts stay pending.

    Only independently known expectations are tested: allowed verdict range,
    prohibited response action, and required uncertainty concepts.
    """
    labels_file = Path(labels_path)
    labels = json.loads(labels_file.read_text(encoding="utf-8"))
    cases = labels.get("cases") if isinstance(labels, Mapping) else None
    if not isinstance(cases, list) or not cases:
        raise ValueError("truth-label manifest requires cases")
    corpus = Path(corpus_dir)
    results = []
    for label in cases:
        if not isinstance(label, Mapping) or not isinstance(label.get("fixture"), str):
            raise ValueError("each truth label requires fixture")
        artifact_path = corpus / (Path(label["fixture"]).stem.upper() + ".json")
        if not artifact_path.exists():
            results.append({"fixture": label["fixture"], "state": "missing_artifact", "passed": False})
            continue
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        assessment = artifact.get("assessment") if isinstance(artifact, Mapping) else None
        if not isinstance(assessment, Mapping):
            error = artifact.get("assessment_error") if isinstance(artifact, Mapping) else None
            if isinstance(error, str) and error:
                results.append({"fixture": label["fixture"], "artifact": str(artifact_path), "state": "rejected_model_output", "passed": False, "error": error})
                continue
            results.append({"fixture": label["fixture"], "artifact": str(artifact_path), "state": "pending_model_assessment", "passed": None})
            continue
        allowed = label.get("allowed_verdicts") if isinstance(label.get("allowed_verdicts"), list) else []
        prohibited = set(label.get("must_not_recommend", [])) if isinstance(label.get("must_not_recommend"), list) else set()
        action_items = assessment.get("recommended_actions", []) if isinstance(assessment.get("recommended_actions"), list) else []
        actions = {
            item if isinstance(item, str) else item.get("category")
            for item in action_items if isinstance(item, (str, Mapping))
        }
        unknowns = " ".join(item for item in assessment.get("unknowns", []) if isinstance(item, str)).casefold()
        required = label.get("required_unknown_keywords", [])
        required = required if isinstance(required, list) else []
        checks = {
            "allowed_verdict": assessment.get("verdict") in allowed,
            "no_prohibited_action": not actions.intersection(prohibited),
            "required_uncertainty": all(isinstance(keyword, str) and keyword.casefold() in unknowns for keyword in required),
        }
        results.append({"fixture": label["fixture"], "artifact": str(artifact_path), "state": "scored", "passed": all(checks.values()), "checks": checks})
    scored = [item for item in results if item["state"] == "scored"]
    return {
        "cases": len(results), "scored_cases": len(scored),
        "pending_cases": sum(item["state"] == "pending_model_assessment" for item in results),
        "rejected_model_outputs": sum(item["state"] == "rejected_model_output" for item in results),
        "truth_label_gate_passed": bool(scored) and all(item["passed"] for item in scored),
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Score generic corpus assessments against controlled lab labels")
    parser.add_argument("--labels", default="benchmarks/generic_v1_truth_labels.json")
    parser.add_argument("--corpus-dir", default="data/benchmark_corpus")
    args = parser.parse_args()
    result = evaluate_truth_labels(args.labels, args.corpus_dir)
    print(json.dumps(result, indent=2))
    return 0 if result["truth_label_gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
