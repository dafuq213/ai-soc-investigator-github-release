"""Deterministic, bounded transformations that turn encoded telemetry into auditable evidence."""
from __future__ import annotations

import base64
import re

try:
    from .case_models import InvestigationCase
except ImportError:
    from case_models import InvestigationCase


_ENCODED_COMMAND = re.compile(r"(?i)-(?:encodedcommand|enc)\s+([^\s\"']+)")


def decode_powershell_commands(case: InvestigationCase, max_decoded_bytes: int = 8192) -> InvestigationCase:
    """Decode only observed PowerShell -EncodedCommand values; never execute them."""
    original_evidence = list(case.evidence)
    for evidence in original_evidence:
        fields = evidence.record.get("event", {}).get("data", {}).get("win", {}).get("eventdata", {})
        if not isinstance(fields, dict):
            continue
        image, command = str(fields.get("image", "")), str(fields.get("commandLine", ""))
        match = _ENCODED_COMMAND.search(command)
        if "powershell" not in image.lower() or not match:
            continue
        try:
            raw = base64.b64decode(match.group(1), validate=True)
            if not raw or len(raw) > max_decoded_bytes:
                continue
            decoded = raw.decode("utf-16le")
        except (ValueError, UnicodeDecodeError):
            continue
        null_count = decoded.count("\x00")
        normalized = decoded.replace("\x00", "")
        case.add_derived_evidence("decoded_powershell", {
            "transform": "base64_decode_utf16le",
            # Keep control characters visible for audit. The readable form is
            # used only for description/prompting and never replaces this value.
            "decoded_command_raw": decoded.replace("\x00", "\\u0000"),
            "decoded_command": normalized,
            "embedded_null_count": null_count,
            "normalization_applied": bool(null_count),
            "observed_behavior": _describe_observed_behavior(normalized),
        }, evidence.evidence_id)
    return case


def _describe_observed_behavior(command: str) -> list[str]:
    """Plain-language descriptions of exact observed tokens; no intent is inferred."""
    lowered = command.lower()
    descriptions: list[str] = []
    if "start-process" in lowered and "cmd.exe" in lowered:
        descriptions.append("Starts cmd.exe as a child process.")
    if re.search(r"(?:^|\s|/)whoami(?:\s|$|'|\")", lowered):
        descriptions.append("Runs whoami, which prints the current Windows identity.")
    if "test-netconnection" in lowered:
        descriptions.append("Attempts a TCP connectivity check to the host and port shown in the command; success is not established by the command text alone.")
    if "write-output" in lowered:
        descriptions.append("Writes a text string to standard output.")
    return descriptions or ["No supported plain-language behavior summary is available; review the decoded command directly."]
