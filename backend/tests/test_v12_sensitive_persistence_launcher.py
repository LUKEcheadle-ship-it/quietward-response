from __future__ import annotations

from pathlib import Path


def test_root_sensitive_persistence_launcher_bootstraps_backend_path() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (root / "audit_sensitive_persistence.py").read_text(encoding="utf-8")
    assert 'BACKEND = ROOT / "backend"' in source
    assert "sys.path.insert(0, value)" in source
    assert "from scripts.audit_sensitive_persistence import main" in source
    assert "raise SystemExit(main())" in source
