from __future__ import annotations

from typing import Any, Mapping


# The bridge is intentionally a privacy-reducing boundary, not a generic export
# of QuietWard's durable event JSON.  Only fields needed for Response correlation,
# deterministic recommendations, and operator-facing severity context cross it.
_SAFE_ATTRIBUTE_KEYS = {
    # Process pseudonymous/bounded context.
    "pid",
    "ppid",
    "user_identity_hash",
    "command_name",
    "args_hash",
    # File identities without paths/content.
    "changed_fields",
    "previous_sha256",
    "current_sha256",
    "exists",
    # Network identities without raw addresses.
    "protocol",
    "port",
    "destination_hash",
    "remote_address_hash",
    "destination_port",
    "destination_scope",
    "process_name",
    "external_bind",
    "external_destination",
    # Persistence/account identities without raw names/commands/accounts.
    "category",
    "change_type",
    "previous_fingerprint",
    "current_fingerprint",
    # Authentication pseudonyms/counts.
    "source_address_hash",
    "failed_count",
    "source_failed_count",
    "distinct_accounts",
    "credential_spray_candidate",
    "address_identity",
    # Container/integrity bounded identities.
    "container_id_hash",
    "previous_security_fingerprint",
    "current_security_fingerprint",
    "restart_count",
    "previous_restart_count",
    "health_status",
    # Detection/decision context.
    "suspicious_markers",
    "risk_markers",
    "security_markers",
    "known_bad_hash",
    "privileged_context",
    "persistence_indicator",
    "baseline_deviation",
    # Privacy attestations are booleans/labels, not the raw values themselves.
    "raw_arguments_persisted",
    "raw_username_persisted",
    "raw_remote_address_persisted",
    "raw_local_address_persisted",
    "raw_source_address_persisted",
    "raw_destination_address_persisted",
    "raw_file_content_persisted",
    "raw_content_persisted",
    "raw_persistence_content_persisted",
    "raw_authorized_keys_persisted",
    "raw_container_id_persisted",
}

_SAFE_PROCESS_KEYS = {
    "pid",
    "ppid",
    "user_identity_hash",
    "command_name",
    "args_hash",
    "suspicious_markers",
    "privileged_context",
}
_SAFE_FILE_KEYS = {
    "changed_fields",
    "previous_sha256",
    "current_sha256",
    "sha256",
    "hash",
    "exists",
    "known_bad_hash",
}
_SAFE_NETWORK_KEYS = {
    "protocol",
    "port",
    "destination_hash",
    "remote_address_hash",
    "destination_port",
    "destination_scope",
    "process_name",
    "external_bind",
    "external_destination",
}
_SAFE_PERSISTENCE_KEYS = {
    "category",
    "change_type",
    "previous_fingerprint",
    "current_fingerprint",
    "risk_markers",
}
_SAFE_METADATA_KEYS = {
    "operating_system",
    "adapter",
    "quietward_database_read_only",
    "credential_scope",
}
_SAFE_ASSESSMENT_KEYS = {"severity", "score"}


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _pick(value: Any, allowed: set[str]) -> dict[str, Any]:
    source = _mapping(value)
    return {key: source[key] for key in allowed if key in source}


def sanitize_quietward_event_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return the least-privilege QuietWard event accepted by the event-only client.

    Raw detector subjects, arbitrary attributes, local/remote addresses, file paths,
    persistence command/account values, and unrecognized metadata are dropped even
    if a future detector release adds them.  The server receives only bounded typed
    correlation evidence and pseudonymous/hash identities.
    """

    result = dict(payload)

    evidence = _mapping(result.get("evidence"))
    safe_evidence: dict[str, Any] = {}
    for key in ("quietward_event_id", "quietward_source"):
        if key in evidence:
            safe_evidence[key] = evidence[key]
    assessment = _pick(evidence.get("assessment"), _SAFE_ASSESSMENT_KEYS)
    if assessment:
        safe_evidence["assessment"] = assessment
    attributes = _pick(evidence.get("attributes"), _SAFE_ATTRIBUTE_KEYS)
    if attributes:
        safe_evidence["attributes"] = attributes
    result["evidence"] = safe_evidence

    process = _pick(result.get("process"), _SAFE_PROCESS_KEYS)
    result["process"] = process or None

    file_value = _pick(result.get("file"), _SAFE_FILE_KEYS)
    result["file"] = file_value or None

    network = _pick(result.get("network"), _SAFE_NETWORK_KEYS)
    result["network"] = network or None

    persistence = _pick(result.get("persistence"), _SAFE_PERSISTENCE_KEYS)
    result["persistence"] = persistence or None

    result["metadata"] = _pick(result.get("metadata"), _SAFE_METADATA_KEYS)
    return result
