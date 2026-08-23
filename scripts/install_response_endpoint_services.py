#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import platform
import stat
import subprocess
import sys
from pathlib import Path

from response_agent_v12 import AgentConfig


class ServiceInstallError(RuntimeError):
    pass


def _quote(value: object) -> str:
    text = str(value).replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def _unit(
    *,
    description: str,
    exec_argv: list[str],
    read_write_paths: tuple[Path, ...],
) -> str:
    lines = [
        "[Unit]",
        f"Description={description}",
        "After=network-online.target",
        "Wants=network-online.target",
        "",
        "[Service]",
        "Type=simple",
        "ExecStart=" + " ".join(_quote(item) for item in exec_argv),
        "Restart=on-failure",
        "RestartSec=5",
        "TimeoutStopSec=30",
        "UMask=0077",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "RestrictSUIDSGID=true",
        "LockPersonality=true",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
    ]
    for path in read_write_paths:
        lines.append("ReadWritePaths=" + _quote(path))
    lines.extend(["", "[Install]", "WantedBy=default.target", ""])
    return "\n".join(lines)


def _write_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    data = content.encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short service-unit write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def _systemctl(*args: str) -> None:
    completed = subprocess.run(
        ["systemctl", "--user", *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = " ".join((completed.stderr or completed.stdout).split())[:1000]
        raise ServiceInstallError(f"systemctl --user {' '.join(args)} failed: {detail}")


def install(
    *,
    config_path: Path,
    quietward_db_path: Path | None,
    start: bool,
) -> tuple[Path, ...]:
    if platform.system().lower() != "linux":
        raise ServiceInstallError("this installer is for Linux systemd user services only")
    config_path = config_path.expanduser().resolve()
    config = AgentConfig.from_file(config_path)
    repo_root = Path(__file__).resolve().parents[1]
    python = Path(sys.executable).resolve()
    unit_dir = Path("~/.config/systemd/user").expanduser()

    config.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    writable = [config.state_dir, Path(config.quarantine_dir)]
    writable.extend(config.managed_roots)
    unique_writable = tuple(dict.fromkeys(path.resolve() for path in writable))

    agent_unit = unit_dir / "quietward-response-agent.service"
    _write_private(
        agent_unit,
        _unit(
            description="QuietWard Response capability-aware endpoint agent",
            exec_argv=[
                str(python),
                str(repo_root / "scripts" / "poll_response_agent.py"),
                "--config",
                str(config_path),
                "--interval-seconds",
                "5",
            ],
            read_write_paths=unique_writable,
        ),
    )
    units = [agent_unit]

    if quietward_db_path is not None:
        quietward_db = quietward_db_path.expanduser().resolve()
        if not quietward_db.is_file() or quietward_db.is_symlink():
            raise ServiceInstallError("QuietWard database must be an existing regular non-symlink file")
        adapter_unit = unit_dir / "quietward-response-adapter.service"
        _write_private(
            adapter_unit,
            _unit(
                description="QuietWard read-only event adapter for QuietWard Response",
                exec_argv=[
                    str(python),
                    str(repo_root / "scripts" / "quietward_event_adapter.py"),
                    "--config",
                    str(config_path),
                    "--quietward-db",
                    str(quietward_db),
                    "--interval-seconds",
                    "5",
                ],
                read_write_paths=(config.state_dir.resolve(),),
            ),
        )
        units.append(adapter_unit)

    _systemctl("daemon-reload")
    if start:
        for unit in units:
            _systemctl("enable", "--now", unit.name)
    return tuple(units)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install hardened current-user systemd services for the Response agent and optional QuietWard adapter."
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--quietward-db", type=Path)
    parser.add_argument("--no-start", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    units = install(
        config_path=args.config,
        quietward_db_path=args.quietward_db,
        start=not args.no_start,
    )
    for unit in units:
        print(unit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
