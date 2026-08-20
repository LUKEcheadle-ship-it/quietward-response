from __future__ import annotations

import pytest

from app.services.response_family import infer_response_family


@pytest.mark.parametrize(
    ("event_type", "category", "expected"),
    [
        ("ransomware_detected", "", "malware"),
        ("trojan_file_found", "security", "malware"),
        # High-signal event vocabulary wins over a broad vendor category.
        ("ransomware_detected", "execution", "malware"),
        ("credential_spray_detected", "network", "identity"),
        ("credential_dumping_detected", "execution", "identity"),
        ("token_theft_alert", "", "identity"),
        ("phishing_account_takeover", "", "identity"),
        ("ssh_brute_force", "", "identity"),
        ("sudo_abuse_detected", "", "privilege"),
        ("scheduled_task_created", "", "persistence"),
        ("registry_run_added", "", "persistence"),
        ("new_service_created", "", "persistence"),
        ("dns_tunnel_detected", "", "network"),
        ("c2_beacon_detected", "execution", "network"),
        ("data_exfiltration_detected", "", "network"),
        ("lateral_movement_remote_service", "", "network"),
        ("kubernetes_pod_security_violation", "", "container"),
        ("container_escape_attempt", "", "container"),
        ("cve_2026_1234_detected", "", "vulnerability"),
        ("security_misconfiguration", "", "vulnerability"),
        ("audit_log_tamper", "", "integrity"),
        ("audit_log_clear_detected", "execution", "integrity"),
        ("defense_evasion_detected", "", "integrity"),
        ("sensor_offline", "", "integrity"),
        ("encoded_command_execution", "", "execution"),
        ("web_shell_activity", "", "execution"),
        ("living_off_the_land_activity", "", "execution"),
        ("sensitive_file_modified", "", "file_integrity"),
        ("disk_full", "", "operational"),
        ("vendor_specific_event", "authentication", "identity"),
        ("vendor_specific_event", "credential_access", "identity"),
        ("vendor_specific_event", "command_and_control", "network"),
        ("vendor_specific_event", "lateral_movement", "network"),
        ("vendor_specific_event", "defense_evasion", "integrity"),
        ("vendor_specific_event", "availability", "operational"),
        ("novel_signal", "unmapped", "unknown"),
    ],
)
def test_response_family_inference_handles_common_sensor_vocabulary(
    event_type: str,
    category: str,
    expected: str,
) -> None:
    assert infer_response_family(event_type, category) == expected
