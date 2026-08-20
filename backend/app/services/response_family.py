from __future__ import annotations


_EXACT_EVENT_FAMILIES: dict[str, str] = {
    "malware_signature": "malware",
    "yara_match": "malware",
    "executable_created": "malware",
    "sensitive_file_change": "file_integrity",
    "file_change": "file_integrity",
    "process_start": "execution",
    "privilege_escalation": "privilege",
    "auth_failure": "identity",
    "account_change": "identity",
    "persistence_change": "persistence",
    "new_listening_port": "network",
    "outbound_connection": "network",
    "container_escape_indicator": "container",
    "container_change": "container",
    "container_configuration_change": "container",
    "package_vulnerability": "vulnerability",
    "configuration_weakness": "vulnerability",
    "self_integrity_change": "integrity",
    "evidence_integrity_failure": "integrity",
    "collector_health": "integrity",
    "quietward_demo_service_unhealthy": "demo",
    "demo_service_unhealthy": "demo",
}

_CATEGORY_FAMILIES: dict[str, str] = {
    "malware": "malware",
    "file": "file_integrity",
    "file_integrity": "file_integrity",
    "execution": "execution",
    "process": "execution",
    "privilege": "privilege",
    "identity": "identity",
    "authentication": "identity",
    "persistence": "persistence",
    "network": "network",
    "container": "container",
    "vulnerability": "vulnerability",
    "configuration": "vulnerability",
    "integrity": "integrity",
    "operational": "operational",
    "availability": "operational",
}

# Ordered from more specific/high-signal families toward broad fallbacks.
_EVENT_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "malware",
        (
            "ransomware",
            "trojan",
            "virus",
            "worm",
            "malware",
            "malicious_file",
            "malicious_artifact",
            "bad_hash",
            "yara",
        ),
    ),
    (
        "identity",
        (
            "credential_spray",
            "password_spray",
            "brute_force",
            "login_failure",
            "authentication_failure",
            "suspicious_login",
            "impossible_travel",
            "account_takeover",
            "credential_theft",
            "session_hijack",
        ),
    ),
    (
        "privilege",
        (
            "privilege_escalation",
            "privilege_change",
            "sudo_abuse",
            "admin_group_change",
            "root_access",
        ),
    ),
    (
        "persistence",
        (
            "scheduled_task",
            "cron_change",
            "startup_entry",
            "autorun",
            "persistence",
            "service_created",
            "service_install",
        ),
    ),
    (
        "network",
        (
            "command_and_control",
            "c2_",
            "beacon",
            "dns_tunnel",
            "exfiltration",
            "suspicious_connection",
            "port_scan",
            "new_listener",
            "listening_port",
            "network_connection",
        ),
    ),
    (
        "container",
        (
            "container_escape",
            "container_privilege",
            "container_runtime",
            "docker_",
            "kubernetes_",
            "k8s_",
            "pod_security",
        ),
    ),
    (
        "vulnerability",
        (
            "cve_",
            "vulnerable_package",
            "vulnerability",
            "misconfiguration",
            "weak_configuration",
            "insecure_configuration",
            "exposed_service",
        ),
    ),
    (
        "integrity",
        (
            "tamper",
            "audit_failure",
            "evidence_integrity",
            "sensor_integrity",
            "sensor_disabled",
            "sensor_offline",
            "collector_failure",
            "agent_health",
        ),
    ),
    (
        "execution",
        (
            "suspicious_process",
            "command_execution",
            "script_execution",
            "encoded_command",
            "powershell_activity",
            "shell_activity",
            "process_injection",
        ),
    ),
    (
        "file_integrity",
        (
            "file_change",
            "file_modified",
            "sensitive_file",
            "integrity_change",
        ),
    ),
    (
        "operational",
        (
            "service_unavailable",
            "service_down",
            "disk_full",
            "resource_exhaustion",
            "capacity_exhaustion",
            "health_check_failure",
            "availability_issue",
        ),
    ),
)


def infer_response_family(event_type: str | None, category: str | None) -> str:
    event = str(event_type or "").strip().lower().replace("-", "_").replace(" ", "_")
    raw_category = str(category or "").strip().lower().replace("-", "_").replace(" ", "_")

    exact = _EXACT_EVENT_FAMILIES.get(event)
    if exact is not None:
        return exact

    category_family = _CATEGORY_FAMILIES.get(raw_category)
    if category_family is not None:
        return category_family

    for family, hints in _EVENT_HINTS:
        if any(hint in event for hint in hints):
            return family

    return "unknown"
