"""Create and verify a local, Git-independent V1 benchmark baseline lock."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


BASELINE_FILES = (
    "config/alert_scope.json",
    "src/alert_scope.py",
    "src/normalized_alert.py",
    "src/entity_collection.py",
    "src/entity_collection_executor.py",
    "src/evidence_packet.py",
    "src/generic_assessment.py",
    "src/generic_reporting.py",
    "src/generic_response_guidance.py",
    "src/investigate_generic.py",
)


def create_baseline_lock(root: str | Path) -> dict[str, Any]:
    """Return hashes of every implementation file frozen for the held-out run."""
    repository = Path(root)
    hashes: dict[str, str] = {}
    for relative in BASELINE_FILES:
        file = repository / relative
        if not file.exists():
            raise ValueError(f"baseline file is missing: {relative}")
        hashes[relative] = hashlib.sha256(file.read_bytes()).hexdigest()
    return {"schema_version": "v1_baseline_lock_v1", "files": hashes}


def write_baseline_lock(path: str | Path, root: str | Path) -> dict[str, Any]:
    payload = create_baseline_lock(root)
    lock = Path(path)
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def verify_baseline_lock(path: str | Path, root: str | Path) -> dict[str, Any]:
    """Report changes from the frozen baseline without modifying files."""
    lock = Path(path)
    payload = json.loads(lock.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != "v1_baseline_lock_v1" or not isinstance(payload.get("files"), dict):
        raise ValueError("baseline lock has an unsupported schema")
    expected = payload["files"]
    current = create_baseline_lock(root)["files"]
    changed = sorted(relative for relative, digest in expected.items() if current.get(relative) != digest)
    return {"lock": str(lock), "files": len(expected), "changed": changed, "baseline_verified": not changed}


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or verify the local V1 held-out benchmark baseline")
    parser.add_argument("--lock", default="benchmarks/v1_baseline_lock.json")
    parser.add_argument("--root", default=".")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true")
    action.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    try:
        result = write_baseline_lock(args.lock, args.root) if args.write else verify_baseline_lock(args.lock, args.root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "message": str(exc)}))
        return 2
    print(json.dumps({"ok": True, **result}, indent=2))
    return 0 if args.write or result["baseline_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
