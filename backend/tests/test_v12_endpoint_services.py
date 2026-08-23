from __future__ import annotations

from pathlib import Path

from scripts.install_response_endpoint_services import _unit


def test_linux_agent_unit_is_continuous_and_hardened(tmp_path: Path) -> None:
    text = _unit(
        description="test",
        exec_argv=[
            "/usr/bin/python3",
            "/repo/scripts/poll_response_agent.py",
            "--config",
            "/home/test/agent.json",
            "--interval-seconds",
            "5",
        ],
        read_write_paths=(tmp_path.resolve(),),
    )
    for fragment in (
        "Restart=on-failure",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "RestrictSUIDSGID=true",
        "LockPersonality=true",
        "UMask=0077",
        "poll_response_agent.py",
    ):
        assert fragment in text
    assert "--once" not in text


def test_endpoint_installers_do_not_embed_secret_values() -> None:
    root = Path(__file__).resolve().parents[2]
    linux = (root / "scripts" / "install_response_endpoint_services.py").read_text(
        encoding="utf-8"
    )
    windows = (root / "scripts" / "install_response_endpoint_tasks.ps1").read_text(
        encoding="utf-8"
    )
    assert "config.secret" not in linux
    assert "$secret" not in windows.lower()
    assert "--config" in linux and "--config" in windows
    assert "forward_quietward_events.py" in linux
    assert "forward_quietward_events.py" in windows


def test_windows_task_is_current_user_limited_and_continuous() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (root / "scripts" / "install_response_endpoint_tasks.ps1").read_text(
        encoding="utf-8"
    )
    assert "-RunLevel Limited" in source
    assert "-AtLogOn" in source
    assert "poll_response_agent.py" in source
    assert "--once" not in source
    assert "QuietWard Response Adapter" in source
