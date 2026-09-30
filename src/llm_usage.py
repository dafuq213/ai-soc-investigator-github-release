"""Local, append-only usage accounting for paid LLM calls.

The ledger deliberately stores metadata and token counts only. Prompts, model
responses, API keys, and alert evidence are never written here.
"""
from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class BudgetExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class ModelPricing:
    input_usd_per_mtok: float
    output_usd_per_mtok: float

    def estimate(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens * self.input_usd_per_mtok + output_tokens * self.output_usd_per_mtok) / 1_000_000


@dataclass(frozen=True)
class UsageRecord:
    timestamp: str
    case_id: str
    stage: str
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    estimated_usd: float


class UsageLedger:
    """Enforces a simple total spend limit before a new paid request begins."""
    def __init__(self, path: Path, ceiling_usd: float):
        if ceiling_usd <= 0:
            raise ValueError("usage ceiling must be positive")
        self.path, self.ceiling_usd = path, ceiling_usd

    def total_usd(self) -> float:
        if not self.path.exists():
            return 0.0
        total = 0.0
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                value = json.loads(line)
                total += float(value["estimated_usd"])
            except (TypeError, ValueError, KeyError, json.JSONDecodeError):
                # A corrupt record must not stop an investigation. It is ignored
                # rather than interpreted as a spend value.
                continue
        return total

    def ensure_can_start(self, reserved_usd: float = 0.0) -> None:
        if reserved_usd < 0:
            raise ValueError("reserved spend cannot be negative")
        if self.total_usd() + reserved_usd > self.ceiling_usd:
            raise BudgetExceeded(
                f"paid LLM spend ceiling ${self.ceiling_usd:.2f} would be exceeded; no new model request was sent"
            )

    def append(self, case_id: str, stage: str, provider: str, model: str, input_tokens: int, output_tokens: int, pricing: ModelPricing) -> UsageRecord:
        if not case_id or stage not in {"assessment", "qa"}:
            raise ValueError("case_id and a supported stage are required")
        if input_tokens < 0 or output_tokens < 0:
            raise ValueError("token counts cannot be negative")
        record = UsageRecord(
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            case_id=case_id, stage=stage, provider=provider, model=model,
            input_tokens=input_tokens, output_tokens=output_tokens,
            estimated_usd=round(pricing.estimate(input_tokens, output_tokens), 8),
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(record), separators=(",", ":")) + "\n")
        return record


def pricing_from_env(prefix: str) -> ModelPricing | None:
    """Return explicit stage pricing, or None for local/unpriced providers."""
    import os
    input_value, output_value = os.getenv(f"{prefix}_INPUT_USD_PER_MTOK"), os.getenv(f"{prefix}_OUTPUT_USD_PER_MTOK")
    if input_value is None and output_value is None:
        return None
    if input_value is None or output_value is None:
        raise ValueError(f"{prefix} input and output pricing must be configured together")
    try:
        pricing = ModelPricing(float(input_value), float(output_value))
    except ValueError as exc:
        raise ValueError(f"{prefix} pricing must be numeric") from exc
    if pricing.input_usd_per_mtok < 0 or pricing.output_usd_per_mtok < 0:
        raise ValueError(f"{prefix} pricing cannot be negative")
    return pricing


def conservative_request_estimate(prompt: str, max_output_tokens: int, pricing: ModelPricing) -> float:
    """Reserve for a request before exact API usage becomes available.

    Three bytes per token plus a 20% margin deliberately overestimates compact
    English/JSON dossiers. The API-returned counts remain the ledger source of
    truth after completion.
    """
    if max_output_tokens < 1:
        raise ValueError("max_output_tokens must be positive")
    input_tokens = math.ceil(len(prompt.encode("utf-8")) / 3 * 1.2)
    return pricing.estimate(input_tokens, max_output_tokens)


def request_cap_from_env(prefix: str, default_usd: float) -> float:
    """Read a hard maximum for one model request, independent of total budget."""
    import os
    try:
        cap = float(os.getenv(f"{prefix}_MAX_REQUEST_USD", str(default_usd)))
    except ValueError as exc:
        raise ValueError(f"{prefix}_MAX_REQUEST_USD must be numeric") from exc
    if cap <= 0:
        raise ValueError(f"{prefix}_MAX_REQUEST_USD must be positive")
    return cap


def ensure_request_within_cap(estimate_usd: float, cap_usd: float, stage: str) -> None:
    if estimate_usd > cap_usd:
        raise BudgetExceeded(
            f"{stage} request estimate ${estimate_usd:.4f} exceeds its per-request cap ${cap_usd:.2f}; no model request was sent"
        )
