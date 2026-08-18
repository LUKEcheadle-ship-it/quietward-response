#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
ENV_FILE = ROOT / ".env"
ENV_EXAMPLE = ROOT / ".env.example"
VENV = ROOT / ".venv"
DEFAULT_ENROLLMENT_TOKEN = "development-enrollment-token-change-me"


def _venv_python() -> Path:
    candidates = (
        VENV / "Scripts" / "python.exe",
        VENV / "bin" / "python",
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise RuntimeError("local virtual environment was not created correctly")


def _ensure_python() -> None:
    if sys.version_info < (3, 12):
        raise RuntimeError(
            f"Python 3.12 or newer is required; found {sys.version.split()[0]}"
        )


def _tool(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise RuntimeError(f"{name} is required but was not found on PATH")
    return resolved


def _npm_command(npm: str, *args: str) -> list[str]:
    # npm is installed as npm.cmd on Windows. Launch it through cmd.exe rather
    # than relying on CreateProcess to execute a batch wrapper directly.
    if os.name == "nt" and Path(npm).suffix.lower() in {".cmd", ".bat"}:
        return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", "npm", *args]
    return [npm, *args]


def _check_node(node: str) -> None:
    result = subprocess.run(
        [node, "--version"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    text = result.stdout.strip().lstrip("v")
    try:
        major = int(text.split(".", 1)[0])
    except ValueError as exc:
        raise RuntimeError(f"could not determine Node.js version from {result.stdout!r}") from exc
    if major < 22:
        raise RuntimeError(f"Node.js 22 or newer is required; found {text}")


def _env_lines(*, persist: bool) -> list[str]:
    if ENV_FILE.exists():
        return ENV_FILE.read_text(encoding="utf-8").splitlines()
    if not persist:
        return ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
    shutil.copyfile(ENV_EXAMPLE, ENV_FILE)
    try:
        ENV_FILE.chmod(0o600)
    except OSError:
        pass
    print("Created .env from .env.example.")
    return ENV_FILE.read_text(encoding="utf-8").splitlines()


def _env_value(lines: list[str], name: str) -> str | None:
    prefix = name + "="
    for line in reversed(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith(prefix):
            value = stripped[len(prefix):].strip()
            return value or None
    return None


def _write_env_value(lines: list[str], name: str, value: str) -> list[str]:
    prefix = name + "="
    output: list[str] = []
    replaced = False
    for line in lines:
        if line.strip().startswith(prefix) and not line.lstrip().startswith("#"):
            output.append(f"{name}={value}")
            replaced = True
        else:
            output.append(line)
    if not replaced:
        output.append(f"{name}={value}")
    return output


def _prepare_env(*, persist: bool) -> list[str]:
    lines = _env_lines(persist=persist)
    environment_token = os.environ.get("QWR_ENROLLMENT_TOKEN", "").strip()
    if environment_token:
        if len(environment_token) < 24:
            raise RuntimeError("QWR_ENROLLMENT_TOKEN must be at least 24 characters")
        return lines

    token = _env_value(lines, "QWR_ENROLLMENT_TOKEN")
    if not token or token == DEFAULT_ENROLLMENT_TOKEN:
        generated = secrets.token_urlsafe(32)
        if persist:
            lines = _write_env_value(lines, "QWR_ENROLLMENT_TOKEN", generated)
            ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
            try:
                ENV_FILE.chmod(0o600)
            except OSError:
                pass
            print("Generated a private local enrollment token in .env.")
        else:
            # Smoke qualification should not leave an untracked .env behind.
            os.environ["QWR_ENROLLMENT_TOKEN"] = generated
    return lines


def _ensure_backend() -> str:
    if not VENV.exists():
        subprocess.run([sys.executable, "-m", "venv", str(VENV)], cwd=ROOT, check=True)
    python = str(_venv_python())
    subprocess.run(
        [python, "-m", "pip", "install", "-q", "-r", str(BACKEND / "requirements.txt")],
        cwd=ROOT,
        check=True,
    )
    subprocess.run([python, "-m", "alembic", "upgrade", "head"], cwd=BACKEND, check=True)
    return python


def _runtime_settings(python: str) -> tuple[str, int]:
    code = (
        "import json; from app.config import get_settings; "
        "s=get_settings(); print(json.dumps({'host': s.api_host, 'port': s.api_port}))"
    )
    result = subprocess.run(
        [python, "-c", code],
        cwd=BACKEND,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    value = json.loads(result.stdout)
    host = str(value["host"])
    port = int(value["port"])
    if not 1 <= port <= 65535:
        raise RuntimeError("QWR_API_PORT must be a valid TCP port")
    return host, port


def _frontend_api_url(lines: list[str], port: int) -> str:
    explicit_environment = os.environ.get("NEXT_PUBLIC_API_URL", "").strip()
    if explicit_environment:
        return explicit_environment.rstrip("/")
    configured = (_env_value(lines, "NEXT_PUBLIC_API_URL") or "").rstrip("/")
    if port != 8002 and configured in {
        "http://localhost:8002",
        "http://127.0.0.1:8002",
    }:
        configured = ""
    return configured or f"http://localhost:{port}"


def _wait_http(url: str, process: subprocess.Popen[object], label: str, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        code = process.poll()
        if code is not None:
            raise RuntimeError(f"{label} exited before becoming ready (exit code {code})")
        try:
            with urlopen(url, timeout=2) as response:
                if 200 <= response.status < 400:
                    return
        except (URLError, OSError) as exc:
            last_error = str(exc)
        time.sleep(0.5)
    detail = f": {last_error}" if last_error else ""
    raise RuntimeError(f"{label} did not become reachable within {int(timeout)} seconds{detail}")


def _terminate(process: subprocess.Popen[object]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description="Start QuietWard Response locally")
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="Start both product surfaces, verify readiness, then exit without persisting a new .env.",
    )
    args = parser.parse_args()

    _ensure_python()
    npm = _tool("npm")
    node = _tool("node")
    _check_node(node)
    lines = _prepare_env(persist=not args.smoke)
    python = _ensure_backend()
    host, port = _runtime_settings(python)

    if not (FRONTEND / "node_modules").is_dir():
        subprocess.run(_npm_command(npm, "ci"), cwd=FRONTEND, check=True)

    frontend_env = os.environ.copy()
    frontend_env["NEXT_PUBLIC_API_URL"] = _frontend_api_url(lines, port)
    frontend_env["NEXT_TELEMETRY_DISABLED"] = "1"

    backend = subprocess.Popen(
        [
            python,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            host,
            "--port",
            str(port),
            "--workers",
            "1",
        ],
        cwd=BACKEND,
    )
    frontend = subprocess.Popen(
        _npm_command(npm, "run", "dev"),
        cwd=FRONTEND,
        env=frontend_env,
    )

    try:
        _wait_http(f"http://127.0.0.1:{port}/health", backend, "Backend")
        _wait_http("http://127.0.0.1:3001/", frontend, "Frontend")

        seed_demo = (os.environ.get("QWR_SEED_DEMO") or _env_value(lines, "QWR_SEED_DEMO") or "false").strip().lower()
        if seed_demo in {"1", "true", "yes", "on"}:
            subprocess.run(
                [python, str(ROOT / "scripts" / "seed_demo.py"), "--api-url", f"http://127.0.0.1:{port}"],
                cwd=ROOT,
                check=True,
            )

        print("\nQuietWard Response is ready.")
        print("Frontend: http://localhost:3001")
        print(f"API:      http://localhost:{port}")
        print(f"API docs: http://localhost:{port}/docs")

        if args.smoke:
            print("PUBLIC QUICK-START SMOKE: PASS")
            return 0

        print("Press Ctrl+C to stop both services.")
        while True:
            backend_code = backend.poll()
            frontend_code = frontend.poll()
            if backend_code is not None:
                raise RuntimeError(f"Backend exited unexpectedly (exit code {backend_code})")
            if frontend_code is not None:
                raise RuntimeError(f"Frontend exited unexpectedly (exit code {frontend_code})")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping QuietWard Response...")
        return 0
    finally:
        _terminate(frontend)
        _terminate(backend)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"Startup failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
