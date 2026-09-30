"""Run controlled generic benchmark artifacts through Ollama only.

This runner does not use ``provider_from_env`` by design. It constructs an
``OllamaProvider`` directly, making a paid-provider call impossible from this
command even when a shell environment contains Claude credentials.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

try:
    from .generic_assessment import generic_assessment_prompt, parse_generic_assessment
    from .generic_reporting import write_generic_report
    from .llm_providers import OllamaProvider
    from .prompt_audit import persist_prompt_audit, persist_response_audit
    from .truth_label_evaluation import evaluate_truth_labels
except ImportError:
    from generic_assessment import generic_assessment_prompt, parse_generic_assessment
    from generic_reporting import write_generic_report
    from llm_providers import OllamaProvider
    from prompt_audit import persist_prompt_audit, persist_response_audit
    from truth_label_evaluation import evaluate_truth_labels


def assess_corpus_artifact(provider: Any, artifact_path: str | Path, audit_dir: str | Path, run_id: str = "run") -> dict[str, Any]:
    """Assess exactly once, persist its audit, and update the corpus artifact."""
    path = Path(artifact_path)
    artifact = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(artifact, Mapping) or not isinstance(artifact.get("evidence_packet"), Mapping):
        raise ValueError("corpus artifact requires an evidence packet")
    packet = artifact["evidence_packet"]
    case_id = path.stem
    audit_case_id = f"{case_id}-{run_id}"
    prompt = generic_assessment_prompt(packet)
    audit = persist_prompt_audit(
        Path(audit_dir), case_id=audit_case_id, stage="generic_truth_benchmark",
        prompt=prompt, provider="ollama", model=str(getattr(provider, "model", "unknown")),
        contract_version="generic_assessment_v1",
    )
    output = provider.assess_prompt(prompt)
    try:
        assessment = parse_generic_assessment(output, packet)
        error = None
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        assessment = None
        error = str(exc)
    response_path = persist_response_audit(
        Path(audit_dir), case_id=audit_case_id, stage="generic_truth_benchmark",
        response=output, validation_error=error,
    )
    updated = dict(artifact)
    updated["assessment"] = assessment
    updated["assessment_error"] = error
    updated["model_execution"] = {"provider": "ollama", "model": str(getattr(provider, "model", "unknown")), "invoked": True}
    updated["prompt_audit"] = {**audit, "response_path": response_path}
    write_generic_report(packet, assessment, updated["model_execution"], path.with_suffix(".md"), error)
    path.write_text(json.dumps(updated, indent=2, default=str), encoding="utf-8")
    return {"case_id": case_id, "assessment_status": assessment.get("assessment_status") if assessment else "rejected", "error": error}


def run_local_truth_benchmark(labels: str | Path, corpus_dir: str | Path, model: str, base_url: str, audit_dir: str | Path, run_id: str = "run") -> dict[str, Any]:
    """Run every labelled corpus case once through the supplied local model."""
    labels_data = json.loads(Path(labels).read_text(encoding="utf-8"))
    cases = labels_data.get("cases") if isinstance(labels_data, Mapping) else None
    if not isinstance(cases, list) or not cases:
        raise ValueError("truth-label manifest requires cases")
    provider = OllamaProvider(model, base_url=base_url, max_output_tokens=350)
    results, failures = [], []
    for label in cases:
        fixture = label.get("fixture") if isinstance(label, Mapping) else None
        if not isinstance(fixture, str):
            raise ValueError("truth-label case requires fixture")
        artifact = Path(corpus_dir) / (Path(fixture).stem.upper() + ".json")
        try:
            results.append(assess_corpus_artifact(provider, artifact, audit_dir, run_id))
        except Exception as exc:
            failures.append({"artifact": str(artifact), "error": str(exc)})
    score = evaluate_truth_labels(labels, corpus_dir)
    return {"provider": "ollama", "model": model, "attempts": len(results), "failures": failures, "truth_label_score": score}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the controlled truth corpus through Ollama only")
    parser.add_argument("--labels", default="benchmarks/generic_v1_truth_labels.json")
    parser.add_argument("--corpus-dir", default="data/benchmark_corpus")
    parser.add_argument("--model", default="qwen2.5:7b-instruct")
    parser.add_argument("--base-url", default="http://localhost:11434")
    parser.add_argument("--audit-dir", default="data/prompt_audits")
    parser.add_argument("--run-id", default="run", help="Required unique label for a new local prompt/model run")
    args = parser.parse_args()
    result = run_local_truth_benchmark(args.labels, args.corpus_dir, args.model, args.base_url, args.audit_dir, args.run_id)
    print(json.dumps(result, indent=2))
    return 0 if not result["failures"] and result["truth_label_score"]["truth_label_gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
