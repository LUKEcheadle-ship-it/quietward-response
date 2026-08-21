from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from scripts.diagnose_response_agent_security import diagnose
from scripts.response_agent import AgentConfig, write_agent_config


def _config(tmp_path: Path, *, process: bool = False, quarantine: bool = False) -> tuple[Path, AgentConfig]:
    state = (tmp_path / "state").resolve()
    managed = (tmp_path / "managed").resolve()
    managed.mkdir()
    config = AgentConfig(
        base_url="http://127.0.0.1:8002",
        agent_id="agent-diagnostic",
        key_id="key-diagnostic",
        secret="diagnostic-secret-value-with-sufficient-length-123456",
        host_id="host-diagnostic",
        state_dir=state,
        managed_roots=(managed,),
        quarantine_dir=(tmp_path / "quarantine").resolve(),
        enable_process_termination=process,
        enable_file_quarantine=quarantine,
    )
    path = (tmp_path / "agent.json").resolve()
    write_agent_config(path, config)
    return path, config


def test_agent_security_diagnostic_is_read_only_and_reports_disabled_mutators_as_pass(tmp_path: Path) -> None:
    path, config = _config(tmp_path)
    before = path.read_bytes()
    checks = diagnose(path)
    after = path.read_bytes()
    assert before == after
    assert not config.state_dir.exists()

    by_name = {item.name: item for item in checks}
    assert by_name["transport"].status == "PASS"
    assert by_name["credential"].status == "PASS"
    assert by_name["process_termination"].status == "PASS"
    assert by_name["file_quarantine"].status == "PASS"


def test_agent_security_diagnostic_warns_when_high_impact_capabilities_are_enabled(tmp_path: Path) -> None:
    path, _ = _config(tmp_path, process=True, quarantine=True)
    checks = diagnose(path)
    assert any(item.name == "process_termination" and item.status == "WARN" for item in checks)
    assert any(item.name == "file_quarantine" and item.status == "WARN" for item in checks)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics")
def test_agent_security_diagnostic_rejects_readable_credential_file(tmp_path: Path) -> None:
    path, _ = _config(tmp_path)
    path.chmod(0o644)
    checks = diagnose(path)
    assert any(
        item.name == "permissions"
        and item.status == "FAIL"
        and "group/world readable" in item.detail
        for item in checks
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX device/symlink semantics")
def test_agent_security_diagnostic_rejects_symlink_config(tmp_path: Path) -> None:
    path, _ = _config(tmp_path)
    link = (tmp_path / "agent-link.json").resolve()
    link.symlink_to(path)
    from scripts.response_agent import ResponseAgentError

    with pytest.raises(ResponseAgentError, match="must not be a symbolic link"):
        diagnose(link)


def test_agent_security_diagnostic_source_does_not_expose_or_mutate_secret() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (root / "scripts" / "diagnose_response_agent_security.py").read_text(
        encoding="utf-8"
    )
    assert "The agent secret was inspected only for length and was not printed." in source
    assert "print(config.secret" not in source
    assert "write_agent_config" not in source
    assert "subprocess" not in source
    assert "os.system" not in source
