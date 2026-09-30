"""Operator-only retention for raw Wazuh archive indices.

This module is intentionally not exposed as an investigation tool.  It can only
delete the oldest ``wazuh-archives-*`` indices after an explicit ``--apply`` and
will never address Wazuh alert indices.
"""
from __future__ import annotations

import argparse
import json
import ssl
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import quote
from urllib.request import Request, urlopen

from src.wazuh_tools import WazuhConfig


DEFAULT_CAP_BYTES = 1610612736  # 1.5 GiB; the remaining 0.5 GiB is VM archive files.
ARCHIVE_PREFIX = "wazuh-archives-"
HttpCall = Callable[[str, str, dict[str, str]], tuple[int, Any]]


@dataclass(frozen=True)
class ArchiveIndex:
    name: str
    bytes: int


class ArchiveRetention:
    """Plan and, only on request, apply a bounded archive-index deletion."""

    def __init__(self, config: WazuhConfig, http: HttpCall | None = None):
        self.config = config
        self._http = http or self._urlopen

    def list_indices(self) -> list[ArchiveIndex]:
        url = f"{self.config.indexer_url}/_cat/indices/{quote(ARCHIVE_PREFIX + '*', safe='*,-')}?format=json&h=index,store.size&bytes=b"
        status, body = self._http("GET", url, self._headers())
        if not 200 <= status < 300 or not isinstance(body, list):
            raise RuntimeError(f"Indexer returned HTTP {status} while listing archive indices")
        indices: list[ArchiveIndex] = []
        for item in body:
            name = str(item.get("index", ""))
            if not name.startswith(ARCHIVE_PREFIX):
                continue
            try:
                size = int(item.get("store.size", 0))
            except (TypeError, ValueError):
                continue
            if size >= 0:
                indices.append(ArchiveIndex(name, size))
        return sorted(indices, key=lambda entry: entry.name)

    def plan(self, cap_bytes: int = DEFAULT_CAP_BYTES) -> dict[str, Any]:
        if cap_bytes <= 0:
            raise ValueError("cap_bytes must be positive")
        indices = self.list_indices()
        total = sum(item.bytes for item in indices)
        remaining = total
        delete: list[ArchiveIndex] = []
        for item in indices:
            if remaining <= cap_bytes:
                break
            delete.append(item)
            remaining -= item.bytes
        return {
            "scope": "raw_telemetry_only",
            "cap_bytes": cap_bytes,
            "current_bytes": total,
            "projected_bytes": remaining,
            "delete": [{"index": item.name, "bytes": item.bytes} for item in delete],
        }

    def apply(self, plan: dict[str, Any]) -> list[str]:
        deleted: list[str] = []
        for item in plan["delete"]:
            name = item["index"]
            if not isinstance(name, str) or not name.startswith(ARCHIVE_PREFIX):
                raise ValueError("refusing an index outside the raw archive scope")
            status, _ = self._http("DELETE", f"{self.config.indexer_url}/{quote(name, safe='-_.')}", self._headers())
            if not 200 <= status < 300:
                raise RuntimeError(f"Indexer returned HTTP {status} while deleting {name}")
            deleted.append(name)
        return deleted

    def _headers(self) -> dict[str, str]:
        import base64
        token = base64.b64encode(f"{self.config.indexer_username}:{self.config.indexer_password}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    def _urlopen(self, method: str, url: str, headers: dict[str, str]) -> tuple[int, Any]:
        context = None if self.config.verify_tls else ssl._create_unverified_context()
        request = Request(url, headers=headers, method=method)
        with urlopen(request, timeout=self.config.timeout_seconds, context=context) as response:
            return response.status, json.loads(response.read().decode())


def main() -> int:
    parser = argparse.ArgumentParser(description="Cap only Wazuh raw archive indices; alert indices are excluded.")
    parser.add_argument("--cap-bytes", type=int, default=DEFAULT_CAP_BYTES)
    parser.add_argument("--apply", action="store_true", help="delete planned oldest raw archive indices")
    args = parser.parse_args()
    retention = ArchiveRetention(WazuhConfig.from_env())
    plan = retention.plan(args.cap_bytes)
    result: dict[str, Any] = {"mode": "apply" if args.apply else "dry_run", "plan": plan}
    if args.apply:
        result["deleted"] = retention.apply(plan)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
