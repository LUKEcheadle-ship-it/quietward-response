from __future__ import annotations

import hashlib
import ipaddress
import socket
from pathlib import Path
from typing import Any

from response_agent_resources import HANDLE_TTL_SECONDS, ResourceError, ResourceHandleStore

MAX_NETWORK_RESULTS = 256
_PROC_TABLES = (
    ("tcp", "ipv4", Path("/proc/net/tcp")),
    ("tcp", "ipv6", Path("/proc/net/tcp6")),
    ("udp", "ipv4", Path("/proc/net/udp")),
    ("udp", "ipv6", Path("/proc/net/udp6")),
)
_TCP_STATES = {
    "01": "established",
    "02": "syn_sent",
    "03": "syn_received",
    "04": "fin_wait_1",
    "05": "fin_wait_2",
    "06": "time_wait",
    "07": "closed",
    "08": "close_wait",
    "09": "last_ack",
    "0A": "listen",
    "0B": "closing",
}


def _fingerprint(parts: tuple[Any, ...]) -> str:
    raw = "|".join(str(item) for item in parts).encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()


def _decode_address(raw: str, family: str) -> str:
    try:
        value = bytes.fromhex(raw)
    except ValueError as exc:
        raise ResourceError("Linux network table contained an invalid address") from exc
    if family == "ipv4":
        if len(value) != 4:
            raise ResourceError("Linux IPv4 network table address length is invalid")
        packed = value[::-1]
        af = socket.AF_INET
    else:
        if len(value) != 16:
            raise ResourceError("Linux IPv6 network table address length is invalid")
        # /proc/net/tcp6 exposes the address as four little-endian 32-bit words.
        packed = b"".join(value[index : index + 4][::-1] for index in range(0, 16, 4))
        af = socket.AF_INET6
    try:
        return socket.inet_ntop(af, packed)
    except OSError as exc:
        raise ResourceError("Linux network address could not be decoded") from exc


def _endpoint(value: str, family: str) -> tuple[str, int]:
    address_raw, separator, port_raw = value.partition(":")
    if separator != ":":
        raise ResourceError("Linux network endpoint format is invalid")
    try:
        port = int(port_raw, 16)
    except ValueError as exc:
        raise ResourceError("Linux network port is invalid") from exc
    return _decode_address(address_raw, family), port


def _scope(address: str) -> str:
    try:
        value = ipaddress.ip_address(address)
    except ValueError:
        return "unknown"
    if value.is_unspecified:
        return "unspecified"
    if value.is_loopback:
        return "loopback"
    if value.is_link_local:
        return "link_local"
    if value.is_multicast:
        return "multicast"
    if value.is_private:
        return "private"
    if value.is_global:
        return "public"
    return "reserved"


def _address_hash(address: str) -> str:
    return hashlib.sha256(("qwr-network-v1:" + address).encode("utf-8")).hexdigest()[:32]


def _read_table(protocol: str, family: str, path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    rows: list[dict[str, Any]] = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        try:
            local_address, local_port = _endpoint(fields[1], family)
            remote_address, remote_port = _endpoint(fields[2], family)
            state_code = fields[3].upper()
            uid = int(fields[7])
            inode = int(fields[9])
        except (ResourceError, ValueError):
            continue
        state = _TCP_STATES.get(state_code, state_code.lower()) if protocol == "tcp" else state_code.lower()
        rows.append(
            {
                "protocol": protocol,
                "family": family,
                "local_address": local_address,
                "local_port": local_port,
                "remote_address": remote_address,
                "remote_port": remote_port,
                "state": state,
                "uid": uid,
                "inode": inode,
            }
        )
    return rows


def collect_network_diagnostic(store: ResourceHandleStore) -> dict[str, Any]:
    if not Path("/proc/net").is_dir():
        raise ResourceError("network diagnostics are currently supported only on Linux /proc hosts")

    all_rows: list[dict[str, Any]] = []
    for protocol, family, path in _PROC_TABLES:
        all_rows.extend(_read_table(protocol, family, path))
    all_rows.sort(
        key=lambda item: (
            str(item["protocol"]),
            str(item["family"]),
            int(item["local_port"]),
            int(item["remote_port"]),
            int(item["inode"]),
        )
    )

    returned: list[dict[str, Any]] = []
    for item in all_rows[:MAX_NETWORK_RESULTS]:
        remote_scope = _scope(str(item["remote_address"]))
        local_scope = _scope(str(item["local_address"]))
        remote_unspecified = remote_scope == "unspecified" and int(item["remote_port"]) == 0
        identity = {
            "protocol": item["protocol"],
            "family": item["family"],
            "local_address": item["local_address"],
            "local_port": item["local_port"],
            "remote_address": item["remote_address"],
            "remote_port": item["remote_port"],
            "state": item["state"],
            "uid": item["uid"],
            "inode": item["inode"],
        }
        fingerprint = _fingerprint(
            (
                identity["protocol"],
                identity["family"],
                identity["local_address"],
                identity["local_port"],
                identity["remote_address"],
                identity["remote_port"],
                identity["state"],
                identity["uid"],
                identity["inode"],
            )
        )
        display = {
            "protocol": item["protocol"],
            "family": item["family"],
            "local_scope": local_scope,
            "local_port": int(item["local_port"]),
            "remote_scope": remote_scope,
            "remote_port": int(item["remote_port"]),
            "remote_address_sha256": None
            if remote_unspecified
            else _address_hash(str(item["remote_address"])),
            "state": item["state"],
        }
        row = dict(display)
        row.update(
            store.issue(
                kind="network_socket",
                identity=identity,
                fingerprint=fingerprint,
                display=display,
                ttl_seconds=HANDLE_TTL_SECONDS,
            )
        )
        returned.append(row)

    return {
        "read_only": True,
        "system_state_changed": False,
        "platform": "Linux",
        "resource_handle_ttl_seconds": HANDLE_TTL_SECONDS,
        "connections": returned,
        "truncated": len(all_rows) > MAX_NETWORK_RESULTS,
        "raw_network_addresses_returned": False,
    }
