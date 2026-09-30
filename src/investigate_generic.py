"""Generic V1 investigation: Wazuh alert → entity collection → one LLM assessment."""
from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

try:
    from .alert_scope import AlertScope
    from .entity_collection import plan_entity_collection
    from .entity_collection_executor import execute_entity_collection
    from .evidence_packet import build_evidence_packet
    from .generic_assessment import generic_assessment_prompt, parse_generic_assessment
    from .generic_reporting import write_generic_report
    from .llm_providers import ModelProvider, provider_from_env
    from .llm_usage import BudgetExceeded, UsageLedger, conservative_request_estimate, ensure_request_within_cap, request_cap_from_env
    from .normalized_alert import normalize_alert
    from .prompt_audit import persist_prompt_audit, persist_response_audit
    from .wazuh_tools import WazuhConfig, WazuhToolLayer
    from .env_config import load_project_env
except ImportError:
    from alert_scope import AlertScope
    from entity_collection import plan_entity_collection
    from entity_collection_executor import execute_entity_collection
    from evidence_packet import build_evidence_packet
    from generic_assessment import generic_assessment_prompt, parse_generic_assessment
    from generic_reporting import write_generic_report
    from llm_providers import ModelProvider, provider_from_env
    from llm_usage import BudgetExceeded, UsageLedger, conservative_request_estimate, ensure_request_within_cap, request_cap_from_env
    from normalized_alert import normalize_alert
    from prompt_audit import persist_prompt_audit, persist_response_audit
    from wazuh_tools import WazuhConfig, WazuhToolLayer
    from env_config import load_project_env


def run_generic_investigation(tools: Any, alert_id: str, scope: AlertScope | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Collect a generic bounded evidence packet; this function never calls a model."""
    seed = tools.get_alert_by_id(alert_id)
    if not isinstance(seed, Mapping) or not seed.get("ok") or not isinstance(seed.get("data"), list) or not seed["data"]:
        raise ValueError("alert was not found")
    normalized = normalize_alert(seed["data"][0])
    reasons = scope.exclusion_reasons(normalized) if scope is not None else []
    if reasons:
        raise ValueError("alert is out of investigation scope: " + "; ".join(reasons))
    plan = plan_entity_collection(normalized)
    execution = execute_entity_collection(tools, plan)
    return normalized, build_evidence_packet(normalized, execution)


class AssessmentOutputError(ValueError):
    def __init__(self, message: str, audit: Mapping[str, Any], response_audit: str | None = None):
        super().__init__(message)
        self.audit = dict(audit)
        self.response_audit = response_audit


def new_case_id(now: datetime | None = None) -> str:
    """Return a readable identifier that is safe for rapid or parallel runs."""
    instant = now or datetime.now(timezone.utc)
    return f"GENERIC-{instant:%Y%m%d-%H%M%S-%f}-{uuid4().hex[:6].upper()}"


def assess_packet(provider: ModelProvider, packet: Mapping[str, Any], case_id: str, audit_dir: Path, ledger: UsageLedger | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Make one audited provider request and parse its strict generic contract."""
    prompt = generic_assessment_prompt(packet)
    audit = persist_prompt_audit(audit_dir, case_id=case_id, stage="generic_assessment", prompt=prompt, provider=str(getattr(provider, "provider_name", "unknown")), model=str(getattr(provider, "model", "unknown")), contract_version="generic_assessment_v3")
    paid = getattr(provider, "provider_name", None) == "anthropic"
    pricing = getattr(provider, "pricing", None)
    if paid:
        if pricing is None or ledger is None:
            raise BudgetExceeded("Anthropic pricing and a usage ledger are required; no paid request was sent")
        estimate = conservative_request_estimate(prompt, provider.max_output_tokens, pricing)
        ensure_request_within_cap(estimate, request_cap_from_env("LLM", 0.10), "assessment")
        ledger.ensure_can_start(estimate)
    provider.last_usage = None
    try:
        output = provider.assess_prompt(prompt)
    finally:
        usage = getattr(provider, "last_usage", None)
        if paid and isinstance(usage, dict):
            record = ledger.append(case_id, "assessment", provider.provider_name, provider.model, int(usage["input_tokens"]), int(usage["output_tokens"]), pricing)
            audit["usage"] = asdict(record)
    try:
        assessment = parse_generic_assessment(output, packet)
        return assessment, {**audit, "response_path": persist_response_audit(audit_dir, case_id=case_id, stage="generic_assessment", response=output)}
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        response_path = persist_response_audit(audit_dir, case_id=case_id, stage="generic_assessment", response=output, validation_error=str(exc))
        raise AssessmentOutputError(str(exc), audit, response_path) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Run generic Wazuh alert investigation with one validated LLM assessment")
    parser.add_argument("--alert-id", required=True, help="Exact Wazuh alert ID; quote it in PowerShell")
    parser.add_argument("--case-id", help="Optional report identifier")
    parser.add_argument("--evidence-only", action="store_true", help="Collect and report without a model call")
    parser.add_argument("--scope-config", default="config/alert_scope.json", help="Project intake scope; does not alter Wazuh")
    args = parser.parse_args()
    # CLI configuration supports a Git-ignored project `.env`; explicit shell
    # variables still take precedence over it.
    load_project_env()
    case_id = args.case_id or new_case_id()
    output_dir = Path(__file__).resolve().parent.parent / "data" / "investigations"
    audit_dir = Path(__file__).resolve().parent.parent / "data" / "prompt_audits"
    try:
        normalized, packet = run_generic_investigation(WazuhToolLayer(WazuhConfig.from_env()), args.alert_id, AlertScope.from_path(args.scope_config))
    except Exception as exc:
        print(json.dumps({"ok": False, "alert_id": args.alert_id, "message": str(exc)}))
        return 2
    provider = provider_from_env()
    ledger = UsageLedger(
        Path(os.getenv("LLM_USAGE_LEDGER", Path(__file__).resolve().parent.parent / "data" / "usage" / "llm_usage.jsonl")),
        float(os.getenv("LLM_PROJECT_BUDGET_USD", "4.00")),
    )
    model = {"provider": getattr(provider, "provider_name", "unknown"), "model": getattr(provider, "model", "unknown"), "invoked": False}
    assessment: dict[str, Any] | None = None
    audit: dict[str, Any] | None = None
    error: str | None = None
    if not args.evidence_only:
        try:
            assessment, audit = assess_packet(provider, packet, case_id, audit_dir, ledger)
            model["invoked"] = True
        except AssessmentOutputError as exc:
            model["invoked"] = True
            error = str(exc)
            audit = {**exc.audit, "response_path": exc.response_audit}
        except Exception as exc:
            model["invoked"] = True
            error = str(exc)
    report = write_generic_report(packet, assessment, model, output_dir / f"{case_id}.md", error)
    json_path = output_dir / f"{case_id}.json"
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps({"normalized_alert": normalized, "evidence_packet": packet, "assessment": assessment, "assessment_error": error, "model_execution": model, "prompt_audit": audit}, indent=2, default=str), encoding="utf-8")
    print(json.dumps({"ok": assessment is not None if not args.evidence_only else True, "case_id": case_id, "alert_id": args.alert_id, "assessment_status": assessment.get("assessment_status", "accepted") if assessment else ("evidence_only" if args.evidence_only else "rejected"), "verdict": assessment.get("verdict") if assessment else "not_assessed", "confidence": assessment.get("confidence") if assessment else None, "model_execution": model, "report": str(report), "packet": str(json_path), "prompt_audit": audit, "project_llm_spend_usd": round(ledger.total_usd(), 8), "error": error}, indent=2))
    return 0 if assessment is not None or args.evidence_only else 1


if __name__ == "__main__":
    raise SystemExit(main())
