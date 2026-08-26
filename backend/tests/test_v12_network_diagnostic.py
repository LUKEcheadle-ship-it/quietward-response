from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from scripts import response_agent_network as network


class _FakeStore:
    def __init__(self, state_dir: Path) -> None:
        self.path = state_dir / "response-agent-resource-handles.json"
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


def _install_tables(tmp_path: Path, monkeypatch, rows: list[str]) -> None:
    tcp = tmp_path / "tcp"
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


def test_read_table_decodes_ipv4_without_returning_raw_address_from_public_diagnostic(tmp_path: Path, monkeypatch) -> None:
    # 127.0.0.1:8080 -> 1.2.3.4:443 in Linux /proc little-endian IPv4 form.
    _install_tables(
        tmp_path,
        monkeypatch,
        [_row(0, "0100007F:1F90", "04030201:01BB")],
    )
    store = _FakeStore(tmp_path / "agent-state")
    result = network.collect_network_diagnostic(store)
    assert result["read_only"] is True
    assert result["system_state_changed"] is False
    assert result["raw_network_addresses_returned"] is False
    assert result["remote_address_identity"] == "endpoint_local_hmac_sha256_128"
    assert result["truncated"] is False
    assert len(result["connections"]) == 1

    row = result["connections"][0]
    assert row["protocol"] == "tcp"
    assert row["local_scope"] == "loopback"
    assert row["local_port"] == 8080
    assert row["remote_scope"] == "public"
    assert row["remote_port"] == 443
    assert row["state"] == "established"
    assert len(row["remote_address_hmac_sha256"]) == 32
    assert row["resource_handle"].startswith("qwrh1_")

    serialized = json.dumps(result, sort_keys=True)
    assert "127.0.0.1" not in serialized
    assert "1.2.3.4" not in serialized

    identity = store.issued[0]["identity"]
    assert identity["local_address"] == "127.0.0.1"
    assert identity["remote_address"] == "1.2.3.4"
    assert store.issued[0]["kind"] == "network_socket"

    key_path = store.path.parent / network.NETWORK_PRIVACY_KEY_FILENAME
    assert key_path.read_bytes()
    assert len(key_path.read_bytes()) == network.NETWORK_PRIVACY_KEY_BYTES
    if os.name != "nt":
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(key_path.parent.stat().st_mode) == 0o700


def test_remote_address_pseudonym_is_stable_per_endpoint_but_differs_between_endpoints(tmp_path: Path, monkeypatch) -> None:
    _install_tables(
        tmp_path,
        monkeypatch,
        [_row(0, "0100007F:1F90", "04030201:01BB")],
    )
    first_store = _FakeStore(tmp_path / "agent-a")
    second_store = _FakeStore(tmp_path / "agent-b")

    first = network.collect_network_diagnostic(first_store)["connections"][0][
        "remote_address_hmac_sha256"
    ]
    repeated = network.collect_network_diagnostic(first_store)["connections"][0][
        "remote_address_hmac_sha256"
    ]
    second = network.collect_network_diagnostic(second_store)["connections"][0][
        "remote_address_hmac_sha256"
    ]
    assert first == repeated
    assert first != second


def test_network_diagnostic_is_bounded_and_marks_truncation(tmp_path: Path, monkeypatch) -> None:
    rows = [
        _row(
            index,
            f"0100007F:{(10000 + index) & 0xFFFF:04X}",
            f"04030201:{(20000 + index) & 0xFFFF:04X}",
            inode=20000 + index,
        )
        for index in range(network.MAX_NETWORK_RESULTS + 25)
    ]
    _install_tables(tmp_path, monkeypatch, rows)
    store = _FakeStore(tmp_path / "agent-state")
    result = network.collect_network_diagnostic(store)
    assert len(result["connections"]) == network.MAX_NETWORK_RESULTS
    assert len(store.issued) == network.MAX_NETWORK_RESULTS
    assert result["truncated"] is True


def test_unspecified_remote_endpoint_does_not_emit_meaningless_address_pseudonym(tmp_path: Path, monkeypatch) -> None:
    _install_tables(
        tmp_path,
        monkeypatch,
        [_row(0, "00000000:1F90", "00000000:0000", state="0A")],
    )
    result = network.collect_network_diagnostic(_FakeStore(tmp_path / "agent-state"))
    assert result["connections"][0]["remote_scope"] == "unspecified"
    assert result["connections"][0]["remote_port"] == 0
    assert result["connections"][0]["remote_address_hmac_sha256"] is None


def test_insecure_existing_network_privacy_key_fails_closed(tmp_path: Path, monkeypatch) -> None:
    if os.name == "nt":
        pytest.skip("POSIX permission semantics do not apply")
    _install_tables(
        tmp_path,
        monkeypatch,
        [_row(0, "0100007F:1F90", "04030201:01BB")],
    )
    store = _FakeStore(tmp_path / "agent-state")
    store.path.parent.mkdir(parents=True)
    key_path = store.path.parent / network.NETWORK_PRIVACY_KEY_FILENAME
    key_path.write_bytes(b"x" * network.NETWORK_PRIVACY_KEY_BYTES)
    key_path.chmod(0o644)
    with pytest.raises(network.ResourceError, match="permissions are not private"):
        network.collect_network_diagnostic(store)


def test_symlinked_network_privacy_key_fails_closed_without_touching_target(tmp_path: Path, monkeypatch) -> None:
    _install_tables(
        tmp_path,
        monkeypatch,
        [_row(0, "0100007F:1F90", "04030201:01BB")],
    )
    store = _FakeStore(tmp_path / "agent-state")
    store.path.parent.mkdir(parents=True)
    if os.name != "nt":
        store.path.parent.chmod(0o700)
    victim = (tmp_path / "victim.bin").resolve()
    victim.write_bytes(b"v" * network.NETWORK_PRIVACY_KEY_BYTES)
    if os.name != "nt":
        victim.chmod(0o600)
    key_path = store.path.parent / network.NETWORK_PRIVACY_KEY_FILENAME
    try:
        key_path.symlink_to(victim)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable on this host")

    with pytest.raises(network.ResourceError, match="regular private file"):
        network.collect_network_diagnostic(store)
    assert victim.read_bytes() == b"v" * network.NETWORK_PRIVACY_KEY_BYTES


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
