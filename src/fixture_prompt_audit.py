"""Persist the exact compact LLM input for a replayable evidence fixture."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

try:
    from .assessment_dossier import build_dossier
    from .assessment_prompt import assessment_prompt
    from .fixture_replay import replay_fixture
except ImportError:
    from assessment_dossier import build_dossier
    from assessment_prompt import assessment_prompt
    from fixture_replay import replay_fixture


def write_prompt_audit(fixture: dict[str, Any], output_dir: str | Path) -> dict[str, Any]:
    """Write auditable prompt/dossier artifacts without calling an LLM."""
    case, _ = replay_fixture(fixture)
    prompt = assessment_prompt(case)
    dossier = build_dossier(case)
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    prompt_path = target / f"{case.case_id}.assessment-prompt.txt"
    dossier_path = target / f"{case.case_id}.assessment-dossier.json"
    prompt_path.write_text(prompt, encoding="utf-8")
    dossier_path.write_text(json.dumps(dossier, indent=2), encoding="utf-8")
    return {
        "case_id": case.case_id,
        "prompt": str(prompt_path),
        "dossier": str(dossier_path),
        "prompt_chars": len(prompt),
        "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "llm_called": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Save the exact compact assessment prompt for a captured fixture")
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--output-dir", default="data/fixture_reports")
    args = parser.parse_args()
    fixture = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
    print(json.dumps(write_prompt_audit(fixture, args.output_dir), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
