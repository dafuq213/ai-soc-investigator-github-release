"""Minimal, dependency-free local environment-file loader."""
from __future__ import annotations

import os
from pathlib import Path


def load_env_file(path: str | Path, *, override: bool = False) -> set[str]:
    """Load simple ``KEY=VALUE`` pairs without logging their values.

    Existing process variables win unless the caller explicitly asks to
    override them. This avoids silently changing a provider in a live shell.
    """
    loaded: set[str] = set()
    file_path = Path(path)
    if not file_path.exists():
        return loaded
    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or not key.replace("_", "").isalnum():
            continue
        if key in os.environ and not override:
            continue
        value = value.strip()
        if len(value) >= 2 and value[:1] == value[-1:] and value[:1] in {"'", '"'}:
            value = value[1:-1]
        os.environ[key] = value
        loaded.add(key)
    return loaded


def load_project_env(*, override: bool = False) -> set[str]:
    """Load the repository's `.env` file relative to this source module."""
    return load_env_file(Path(__file__).resolve().parent.parent / ".env", override=override)
