"""Immutable-on-write audit records for the exact compact prompts sent to models."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def persist_prompt_audit(
    output_dir: Path,
    *,
    case_id: str,
    stage: str,
    prompt: str,
    provider: str,
    model: str,
    contract_version: str,
) -> dict[str, Any]:
    """Persist the exact prompt before a provider call, without credentials.

    The caller supplies a compact dossier prompt only; raw Wazuh documents and
    provider configuration are deliberately not added by this module.
    """
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt audit requires a non-empty prompt")
    safe_case = re.sub(r"[^A-Za-z0-9._-]+", "_", case_id)
    safe_stage = re.sub(r"[^A-Za-z0-9._-]+", "_", stage)
    digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    record = {
        "case_id": case_id,
        "stage": stage,
        "contract_version": contract_version,
        "provider": provider,
        "model": model,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sha256": digest,
        "characters": len(prompt),
        "prompt": prompt,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{safe_case}-{safe_stage}.json"
    # An attempt always has its own stage suffix. Refusing an accidental
    # overwrite keeps the audit trail honest if a caller reuses a case ID.
    if path.exists():
        raise FileExistsError(f"prompt audit already exists: {path}")
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    return {**{key: record[key] for key in ("stage", "contract_version", "provider", "model", "sha256", "characters")}, "path": str(path)}


def persist_response_audit(output_dir: Path, *, case_id: str, stage: str, response: str, validation_error: str | None = None) -> str:
    """Persist an unmodified model response for post-failure diagnosis.

    The response is never treated as evidence or report content unless the
    caller's contract accepts it. It contains no configuration or credentials.
    """
    safe_case = re.sub(r"[^A-Za-z0-9._-]+", "_", case_id)
    safe_stage = re.sub(r"[^A-Za-z0-9._-]+", "_", stage)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{safe_case}-{safe_stage}-response.json"
    if path.exists():
        raise FileExistsError(f"response audit already exists: {path}")
    path.write_text(json.dumps({"case_id": case_id, "stage": stage, "validation_error": validation_error, "response": response}, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path)
