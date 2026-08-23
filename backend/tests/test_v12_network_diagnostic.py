from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import response_agent_network as network


class _FakeStore:
    def __init__(self) -> None:
        self.issued: list[dict] = []

    def issue(self, **kwargs):
        self.issued.append(dict(kwargs))
        index = len(self.issued)
        return {
            "resource_handle": f"qwrh1_network_test_{index:04d}",
            "resource_kind": kwargs["kind"],
            "expires_at": "2026-08-23T20:00:00+00:00",
        }


def _table(rows: list[str]) -> str:
    return "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" + "\n".join(rows) + "\n"


def _row(index: int, local: str, remote: str, state: str = "01", *, uid: int = 1000, inode: int | None = None) -> str:
    return (
        f"{index}: {local} {remote} {state} "
        f"00000000:00000000 00:00000000 00000000 {uid} 0 {inode or (10000 + index)}"
    )


def test_read_table_decodes_ipv4_without_returning_raw_address_from_public_diagnostic(tmp_path: Path, monkeypatch) -> None:
    tcp = tmp_path / "tcp"
    # 127.0.0.1:8080 -> 1.2.3.4:443 in Linux /proc little-endian IPv4 form.
    tcp.write_text(
        _table([_row(0, "0100007F:1F90", "04030201:01BB")]),
        encoding="utf-8",
    )
    empty = tmp_path / "empty"
    empty.write_text(_table([]), encoding="utf-8")
    monkeypatch.setattr(
        network,
        "_PROC_TABLES",
        (
            ("tcp", "ipv4", tcp),
            ("tcp", "ipv6", empty),
            ("udp", "ipv4", empty),
            ("udp", "ipv6", empty),
        ),
    )
    monkeypatch.setattr(network.Path, "is_dir", lambda self: True)

    store = _FakeStore()
    result = network.collect_network_diagnostic(store)
    assert result["read_only"] is True
    assert result["system_state_changed"] is False
    assert result["raw_network_addresses_returned"] is False
    assert result["truncated"] is False
    assert len(result["connections"]) == 1

    row = result["connections"][0]
    assert row["protocol"] == "tcp"
    assert row["local_scope"] == "loopback"
    assert row["local_port"] == 8080
    assert row["remote_scope"] == "public"
    assert row["remote_port"] == 443
    assert row["state"] == "established"
    assert row["remote_address_sha256"]
    assert row["resource_handle"].startswith("qwrh1_")

    serialized = json.dumps(result, sort_keys=True)
    assert "127.0.0.1" not in serialized
    assert "1.2.3.4" not in serialized

    # Raw addresses are retained only in the agent-local opaque-handle identity.
    identity = store.issued[0]["identity"]
    assert identity["local_address"] == "127.0.0.1"
    assert identity["remote_address"] == "1.2.3.4"
    assert store.issued[0]["kind"] == "network_socket"


def test_network_diagnostic_is_bounded_and_marks_truncation(tmp_path: Path, monkeypatch) -> None:
    tcp = tmp_path / "tcp"
    rows = [
        _row(
            index,
            f"0100007F:{(10000 + index) & 0xFFFF:04X}",
            f"04030201:{(20000 + index) & 0xFFFF:04X}",
            inode=20000 + index,
        )
        for index in range(network.MAX_NETWORK_RESULTS + 25)
    ]
    tcp.write_text(_table(rows), encoding="utf-8")
    empty = tmp_path / "empty"
    empty.write_text(_table([]), encoding="utf-8")
    monkeypatch.setattr(
        network,
        "_PROC_TABLES",
        (
            ("tcp", "ipv4", tcp),
            ("tcp", "ipv6", empty),
            ("udp", "ipv4", empty),
            ("udp", "ipv6", empty),
        ),
    )
    monkeypatch.setattr(network.Path, "is_dir", lambda self: True)

    store = _FakeStore()
    result = network.collect_network_diagnostic(store)
    assert len(result["connections"]) == network.MAX_NETWORK_RESULTS
    assert len(store.issued) == network.MAX_NETWORK_RESULTS
    assert result["truncated"] is True


def test_unspecified_remote_endpoint_does_not_emit_meaningless_address_hash(tmp_path: Path, monkeypatch) -> None:
    tcp = tmp_path / "tcp"
    tcp.write_text(
        _table([_row(0, "00000000:1F90", "00000000:0000", state="0A")]),
        encoding="utf-8",
    )
    empty = tmp_path / "empty"
    empty.write_text(_table([]), encoding="utf-8")
    monkeypatch.setattr(
        network,
        "_PROC_TABLES",
        (("tcp", "ipv4", tcp), ("tcp", "ipv6", empty), ("udp", "ipv4", empty), ("udp", "ipv6", empty)),
    )
    monkeypatch.setattr(network.Path, "is_dir", lambda self: True)

    result = network.collect_network_diagnostic(_FakeStore())
    assert result["connections"][0]["remote_scope"] == "unspecified"
    assert result["connections"][0]["remote_port"] == 0
    assert result["connections"][0]["remote_address_sha256"] is None


def test_network_module_has_no_shell_or_subprocess_primitive() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (root / "scripts" / "response_agent_network.py").read_text(encoding="utf-8")
    for forbidden in (
        "import subprocess",
        "subprocess.run",
        "subprocess.Popen",
        "os.system",
        "shell=True",
    ):
        assert forbidden not in source
