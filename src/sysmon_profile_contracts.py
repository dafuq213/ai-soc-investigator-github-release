"""The data contract for each supported Sysmon investigation profile.

This module is the single source of truth for profile selection, required
correlation keys, and the small field set eligible for a profile dossier.  It
is based on ``docs/generated/sysmon_field_catalog.*`` from real Wazuh archive
samples; it is not an LLM prompt or a detection-rule catalog.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class SysmonProfileContract:
    event_id: str
    profile_id: str
    required_keys: tuple[tuple[str, tuple[str, ...]], ...]
    dossier_fields: tuple[tuple[str, tuple[str, ...]], ...]
    raw_only_fields: tuple[str, ...] = ()

    def values(self, fields: Mapping[str, Any]) -> dict[str, Any]:
        """Return only this profile's named dossier fields, using aliases."""
        return {name: _first_present(fields, aliases) for name, aliases in self.dossier_fields}

    def missing_required(self, fields: Mapping[str, Any]) -> list[str]:
        return [name for name, aliases in self.required_keys if _first_present(fields, aliases) is None]

    def key_values(self, fields: Mapping[str, Any]) -> dict[str, Any]:
        """Return named correlation keys without exposing them to the dossier."""
        return {name: _first_present(fields, aliases) for name, aliases in self.required_keys}


PROFILES: tuple[SysmonProfileContract, ...] = (
    SysmonProfileContract("1", "windows_sysmon_process", (("process_guid", ("processGuid",)),), (
        ("image", ("image",)), ("command_line", ("commandLine",)), ("parent_image", ("parentImage",)),
        ("user", ("user",)), ("integrity_level", ("integrityLevel",)), ("hashes", ("hashes",)),
        ("original_file_name", ("originalFileName",)),
    ), ("parentCommandLine", "currentDirectory", "logonGuid", "logonId", "parentUser")),
    SysmonProfileContract("3", "windows_sysmon_network", (("process_guid", ("processGuid",)),), (
        ("image", ("image",)), ("destination_ip", ("destinationIp",)), ("destination_port", ("destinationPort",)),
        ("destination_hostname", ("destinationHostname",)), ("protocol", ("protocol",)),
        ("initiated", ("initiated",)), ("user", ("user",)),
    )),
    SysmonProfileContract("7", "windows_sysmon_image_load", (("process_guid", ("processGuid",)),), (
        ("image", ("image",)), ("image_loaded", ("imageLoaded",)), ("signed", ("signed",)),
        ("signature_status", ("signatureStatus",)), ("hashes", ("hashes",)), ("user", ("user",)),
    )),
    SysmonProfileContract("10", "windows_sysmon_process_access", (
        ("source_process_guid", ("sourceProcessGuid", "sourceProcessGUID")),
        ("target_process_guid", ("targetProcessGuid", "targetProcessGUID")),
    ), (
        ("source_image", ("sourceImage",)), ("target_image", ("targetImage",)),
        ("granted_access", ("grantedAccess",)), ("source_user", ("sourceUser",)), ("target_user", ("targetUser",)),
    ), ("callTrace", "sourceThreadId")),
    SysmonProfileContract("11", "windows_sysmon_file", (("process_guid", ("processGuid",)),), (
        ("image", ("image",)), ("target_filename", ("targetFilename",)),
        ("creation_utc_time", ("creationUtcTime",)), ("user", ("user",)),
    )),
    SysmonProfileContract("12", "windows_sysmon_registry", (("process_guid", ("processGuid",)),), (
        ("image", ("image",)), ("event_type", ("eventType",)), ("target_object", ("targetObject",)), ("user", ("user",)),
    )),
    SysmonProfileContract("13", "windows_sysmon_registry", (("process_guid", ("processGuid",)),), (
        ("image", ("image",)), ("event_type", ("eventType",)), ("target_object", ("targetObject",)),
        ("details", ("details",)), ("user", ("user",)),
    )),
    SysmonProfileContract("14", "windows_sysmon_registry", (("process_guid", ("processGuid",)),), (
        ("image", ("image",)), ("event_type", ("eventType",)), ("target_object", ("targetObject",)),
        ("new_name", ("newName",)), ("user", ("user",)),
    )),
    SysmonProfileContract("22", "windows_sysmon_dns", (("process_guid", ("processGuid",)),), (
        ("image", ("image",)), ("query_name", ("queryName",)), ("query_status", ("queryStatus",)),
        ("query_results", ("queryResults",)), ("user", ("user",)),
    )),
)

BY_EVENT_ID = {contract.event_id: contract for contract in PROFILES}
PROFILE_BY_EVENT_ID = {event_id: contract.profile_id for event_id, contract in BY_EVENT_ID.items()}


def contract_for_event_id(event_id: str) -> SysmonProfileContract | None:
    return BY_EVENT_ID.get(str(event_id))


def _first_present(fields: Mapping[str, Any], aliases: tuple[str, ...]) -> Any | None:
    for alias in aliases:
        value = fields.get(alias)
        if value not in (None, ""):
            return value
    return None
