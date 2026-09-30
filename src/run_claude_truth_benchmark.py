"""One-shot, metered Claude assessment for a pre-collected controlled packet."""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

try:
    from .env_config import load_project_env
    from .generic_reporting import write_generic_report
    from .investigate_generic import AssessmentOutputError, assess_packet
    from .llm_providers import provider_from_env
    from .llm_usage import UsageLedger
except ImportError:
    from env_config import load_project_env
    from generic_reporting import write_generic_report
    from investigate_generic import AssessmentOutputError, assess_packet
    from llm_providers import provider_from_env
    from llm_usage import UsageLedger


def prepare_controlled_claude_run(artifact_path: str | Path) -> tuple[Mapping[str, Any], Any]:
    """Load a pre-collected packet and require explicit Anthropic selection."""
    load_project_env()
    artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8"))
    packet = artifact.get("evidence_packet") if isinstance(artifact, Mapping) else None
    if not isinstance(packet, Mapping):
        raise ValueError("controlled artifact has no evidence packet")
    provider = provider_from_env()
    if getattr(provider, "provider_name", None) != "anthropic":
        raise ValueError("this one-shot benchmark requires LLM_PROVIDER=anthropic; no model request was sent")
    return packet, provider


def main() -> int:
    parser = argparse.ArgumentParser(description="Run exactly one metered Claude assessment of a controlled evidence packet")
    parser.add_argument("--artifact", required=True, help="Evidence-only controlled corpus JSON")
    parser.add_argument("--case-id", help="Optional distinct output case identifier")
    parser.add_argument("--dry-run", action="store_true", help="Validate provider, packet, and output identity without calling Claude")
    args = parser.parse_args()
    try:
        packet, provider = prepare_controlled_claude_run(args.artifact)
    except Exception as exc:
        print(json.dumps({"ok": False, "message": str(exc)}))
        return 2
    case_id = args.case_id or f"CLAUDE-TRUTH-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"
    if args.dry_run:
        print(json.dumps({"ok": True, "dry_run": True, "provider": provider.provider_name, "model": provider.model, "case_id": case_id, "evidence_items": len(packet.get("evidence", []))}, indent=2))
        return 0
    root = Path(__file__).resolve().parent.parent
    output_dir = root / "data" / "investigations"
    audit_dir = root / "data" / "prompt_audits"
    ledger = UsageLedger(Path(os.getenv("LLM_USAGE_LEDGER", root / "data" / "usage" / "llm_usage.jsonl")), float(os.getenv("LLM_PROJECT_BUDGET_USD", "4.00")))
    assessment = None
    audit = None
    error = None
    model = {"provider": provider.provider_name, "model": provider.model, "invoked": True}
    try:
        assessment, audit = assess_packet(provider, packet, case_id, audit_dir, ledger)
    except AssessmentOutputError as exc:
        audit = {**exc.audit, "response_path": exc.response_audit}
        error = str(exc)
    except Exception as exc:
        error = str(exc)
    report = write_generic_report(packet, assessment, model, output_dir / f"{case_id}.md", error)
    json_path = output_dir / f"{case_id}.json"
    json_path.write_text(json.dumps({"evidence_packet": packet, "assessment": assessment, "assessment_error": error, "model_execution": model, "prompt_audit": audit, "benchmark_source": str(args.artifact)}, indent=2, default=str), encoding="utf-8")
    print(json.dumps({"ok": assessment is not None, "case_id": case_id, "assessment_status": assessment.get("assessment_status") if assessment else "rejected", "verdict": assessment.get("verdict") if assessment else None, "confidence": assessment.get("confidence") if assessment else None, "report": str(report), "artifact": str(json_path), "project_llm_spend_usd": round(ledger.total_usd(), 8), "error": error}, indent=2))
    return 0 if assessment is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
