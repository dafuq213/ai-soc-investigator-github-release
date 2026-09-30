"""Primary operator entry point for a verified Wazuh investigation.

This supersedes the earlier free-form agent loop for live use. Every alert
enters the same profile, dossier, LLM, verifier, critic, and quality-gate path.
"""
from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from .investigate_case import run_case_investigation
    from .llm_providers import provider_from_env, qa_provider_from_env
    from .llm_usage import BudgetExceeded, UsageLedger
    from .llm_usage import conservative_request_estimate, ensure_request_within_cap, request_cap_from_env
    from .assessment_prompt import assessment_prompt
    from .assessment import AssessmentPipeline
    from .qa_review import qa_prompt
    from .report_quality import assess_l3_readiness
    from .verified_reporting import write_verified_report
    from .wazuh_tools import WazuhConfig, WazuhToolLayer
    from .prompt_audit import persist_prompt_audit
except ImportError:
    from investigate_case import run_case_investigation
    from llm_providers import provider_from_env, qa_provider_from_env
    from llm_usage import BudgetExceeded, UsageLedger
    from llm_usage import conservative_request_estimate, ensure_request_within_cap, request_cap_from_env
    from assessment_prompt import assessment_prompt
    from assessment import AssessmentPipeline
    from qa_review import qa_prompt
    from report_quality import assess_l3_readiness
    from verified_reporting import write_verified_report
    from wazuh_tools import WazuhConfig, WazuhToolLayer
    from prompt_audit import persist_prompt_audit


def _tracked_call(provider, case_id: str, stage: str, ledger: UsageLedger, records: list[dict[str, object]], prompt_audits: list[dict[str, object]], call, *args, audit_dir: Path | None = None):
    """Audit the exact compact prompt and record usage before a provider call."""
    provider_name = getattr(provider, "provider_name", None)
    # Never silently send a live case to a provider whose actual API usage is
    # not captured by this command.  Ollama is local; Anthropic returns the
    # exact usage fields we ledger.  Other adapters remain available for
    # development but cannot consume an operator's paid credits here.
    if provider_name in {"openai", "gemini", "claude_cli", "gemini_cli"}:
        raise BudgetExceeded(
            f"{stage} provider {provider_name!r} has no live usage ledger in this command; refusing an untracked request"
        )
    is_assessment = stage.startswith("assessment")
    prompt = assessment_prompt(args[0]) if is_assessment else qa_prompt(args[0], args[1])
    contract_version = "judgment_v2" if is_assessment else "qa_v1"
    audit_dir = audit_dir or Path(__file__).resolve().parent.parent / "data" / "prompt_audits"
    prompt_audits.append(persist_prompt_audit(
        audit_dir, case_id=case_id, stage=stage, prompt=prompt,
        provider=str(provider_name), model=str(getattr(provider, "model", "unknown")),
        contract_version=contract_version,
    ))
    paid = provider_name == "anthropic"
    pricing = getattr(provider, "pricing", None)
    if paid:
        if pricing is None:
            raise BudgetExceeded(f"{stage} Anthropic pricing is not configured; refusing an unmetered paid request")
        estimate = conservative_request_estimate(prompt, provider.max_output_tokens, pricing)
        prefix, default_cap = ("LLM", 0.10) if stage == "assessment" else ("QA", 0.03)
        try:
            ensure_request_within_cap(estimate, request_cap_from_env(prefix, default_cap), stage)
        except ValueError as exc:
            raise BudgetExceeded(str(exc)) from exc
        ledger.ensure_can_start(estimate)
    provider.last_usage = None
    try:
        return call(prompt)
    finally:
        # A provider can receive a billable response and then reject it locally
        # (for example, a truncated response with no text block). Account for
        # returned usage even when the provider raises, otherwise a failed
        # request silently escapes the spend ledger.
        usage = getattr(provider, "last_usage", None)
        if paid and isinstance(usage, dict):
            record = ledger.append(
                case_id, stage, provider.provider_name, provider.model,
                int(usage["input_tokens"]), int(usage["output_tokens"]), pricing,
            )
            records.append(asdict(record))


def _repair_prompt(original_prompt: str, rejected_output: str, error: str) -> str:
    """Request a schema-only correction without adding facts or widening scope."""
    bounded_output = rejected_output[:8_000]
    return (
        f"{original_prompt}\n\n"
        "YOUR PREVIOUS RESPONSE WAS REJECTED BY THE DETERMINISTIC CONTRACT. "
        "Repair it using only the dossier above. Do not add facts, IDs, or explanation outside one JSON object.\n"
        f"Validation error: {error}\n"
        f"Previous response:\n{bounded_output}\n"
        "Return the corrected JSON object only."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a verified, profile-driven Wazuh SOC investigation")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--alert-id", help="Exact Wazuh alert ID")
    source.add_argument("--severity", type=int, choices=range(0, 17), help="Use the newest Wazuh alert at this severity")
    parser.add_argument("--case-id", help="Optional case ID")
    parser.add_argument("--hours", type=int, default=24, choices=range(1, 169), help="Bounded seed-relative collection window")
    parser.add_argument("--evidence-only", action="store_true", help="Skip model assessment and critic")
    parser.add_argument("--skip-qa", action="store_true", help="Skip independent QA (report cannot be L3-ready)")
    parser.add_argument("--local-repairs", type=int, default=0, choices=range(0, 101),
                        help="Repair invalid local assessment output; 0 retries until repeated output")
    # Compatibility only: old invocations supplied this argument. The verified
    # pipeline has no free-form action depth; profile collection is bounded.
    parser.add_argument("--max-steps", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()

    tools = WazuhToolLayer(WazuhConfig.from_env())
    alert_id = args.alert_id
    if not alert_id:
        newest = tools.get_alerts(args.severity, limit=1)
        if not newest.get("ok") or not newest.get("data"):
            print(json.dumps({"ok": False, "message": "no alert found", "tool_result": newest}))
            return 2
        alert_id = newest["data"][0].get("alert_id")
    if not isinstance(alert_id, str) or not alert_id:
        print(json.dumps({"ok": False, "message": "selected alert has no usable alert ID"}))
        return 2

    case_id = args.case_id or f"WAZUH-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"
    provider = provider_from_env()
    qa_provider = qa_provider_from_env()
    usage_ledger = UsageLedger(
        Path(os.getenv("LLM_USAGE_LEDGER", Path(__file__).resolve().parent.parent / "data" / "usage" / "llm_usage.jsonl")),
        float(os.getenv("LLM_PROJECT_BUDGET_USD", "4.00")),
    )
    usage_records: list[dict[str, object]] = []
    prompt_audits: list[dict[str, object]] = []
    model_execution: dict[str, dict[str, object]] = {}

    def describe(provider, invoked: bool) -> dict[str, object]:
        return {
            "provider": getattr(provider, "provider_name", "unknown"),
            "model": getattr(provider, "model", "unknown"),
            "invoked": invoked,
        }

    def tracked_assessment(case):
        model_execution["assessment"] = describe(provider, True)
        # Paid or remote providers make exactly one request unless separately
        # authorized. Local retries only repair a known contract failure.
        if getattr(provider, "provider_name", None) != "ollama":
            return _tracked_call(provider, case.case_id, "assessment-attempt-01", usage_ledger, usage_records, prompt_audits, provider.assess_prompt, case)
        base_prompt = assessment_prompt(case)
        prior_outputs: set[str] = set()
        output = _tracked_call(provider, case.case_id, "assessment-attempt-01", usage_ledger, usage_records, prompt_audits, provider.assess_prompt, case)
        repair_number = 0
        while True:
            preview = AssessmentPipeline().evaluate(case, output)
            if preview.status == "accepted" or output in prior_outputs:
                return output
            prior_outputs.add(output)
            if args.local_repairs and repair_number >= args.local_repairs:
                return output
            repair_number += 1
            # The repaired request contains no new evidence: only the exact
            # compact dossier, rejected output, and validator error.
            repaired_prompt = _repair_prompt(base_prompt, output, preview.error or "invalid assessment output")
            prompt_audits.append(persist_prompt_audit(
                Path(__file__).resolve().parent.parent / "data" / "prompt_audits",
                case_id=case.case_id, stage=f"assessment-repair-{repair_number:02d}", prompt=repaired_prompt,
                provider=provider.provider_name, model=provider.model, contract_version="judgment_v2_repair",
            ))
            provider.last_usage = None
            output = provider.assess_prompt(repaired_prompt)

    def tracked_qa(case, accepted_assessment):
        model_execution["qa"] = describe(qa_provider, True)
        return _tracked_call(qa_provider, case.case_id, "qa", usage_ledger, usage_records, prompt_audits, qa_provider.review_prompt, case, accepted_assessment)
    try:
        case, assessment = run_case_investigation(
            tools, alert_id, reasoning=None, hours=args.hours, case_id=case_id,
            reasoning_producer=None if args.evidence_only else tracked_assessment,
            qa_producer=None if args.evidence_only or args.skip_qa else tracked_qa,
        )
    except (ValueError, BudgetExceeded) as exc:
        print(json.dumps({"ok": False, "alert_id": alert_id, "message": str(exc)}))
        return 2

    if args.evidence_only:
        model_execution = {
            "assessment": describe(provider, False),
            "qa": describe(qa_provider, False),
        }
    elif args.skip_qa and "qa" not in model_execution:
        # Do not imply that a configured remote QA provider was used (or even
        # selected) when the operator explicitly skipped QA.
        model_execution["qa"] = {"provider": "not_requested", "model": "not_requested", "invoked": False}
    case.correlations["model_execution"] = model_execution

    output_dir = Path(__file__).resolve().parent.parent / "data" / "investigations"
    output_dir.mkdir(parents=True, exist_ok=True)
    report = write_verified_report(case, assessment, output_dir / f"{case.case_id}.md")
    (output_dir / f"{case.case_id}.json").write_text(json.dumps({"case": case.to_dict(), "assessment": asdict(assessment), "llm_usage": usage_records, "prompt_audits": prompt_audits}, indent=2, default=str), encoding="utf-8")
    quality = assess_l3_readiness(case, assessment)
    print(json.dumps({
        "ok": True, "case_id": case.case_id, "alert_id": alert_id,
        "assessment_status": assessment.status, "verdict": assessment.verdict,
        "report_quality_score": quality.score, "l3_ready": quality.ready_for_l3,
        "quality_gaps": quality.gaps, "report": str(report),
        "llm_usage": usage_records,
        "prompt_audits": prompt_audits,
        "project_llm_spend_usd": round(usage_ledger.total_usd(), 8),
    }, indent=2))
    return 0 if assessment.status == "accepted" else 1


if __name__ == "__main__":
    raise SystemExit(main())
