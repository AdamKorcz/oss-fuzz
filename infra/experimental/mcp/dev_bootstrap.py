#!/usr/bin/env python3
"""
POSIX-only bootstrap/supervisor for the OSS-Fuzz MCP server.

- Ensures ./.venv exists
- Installs infra/experimental/mcp/requirements.txt
- Optional hot reload: restarts server on code changes without breaking VS Code's MCP connection
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
import venv

ROOT = Path(__file__).resolve().parents[3]  # repo root (…/oss-fuzz)
VENV = ROOT / ".venv"
MCP_DIR = ROOT / "infra" / "experimental" / "mcp"
REQS = MCP_DIR / "requirements.txt"
DEFAULT_SERVER = MCP_DIR / "server.py"

# ---------- venv / deps ----------
def venv_python() -> Path:
    return VENV / "bin" / "python3"

def ensure_venv() -> Path:
    py = venv_python()
    if not py.exists():
        print("[mcp-bootstrap] creating .venv", flush=True)
        venv.EnvBuilder(with_pip=True).create(str(VENV))
    return py

def pip(py: Path, *args: str):
    cmd = [str(py), "-m", "pip", *args]
    print("[mcp-bootstrap] $", " ".join(cmd), flush=True)
    subprocess.check_call(cmd)

def ensure_requirements(py: Path, ensure_watchfiles: bool):
    if REQS.exists():
        pip(py, "install", "-r", str(REQS))
    else:
        print(f"[mcp-bootstrap] WARNING: {REQS} not found; skipping dependency install", flush=True)
    if ensure_watchfiles:
        # Always make sure watchfiles is present in the venv for hot mode
        pip(py, "install", "watchfiles>=0.21")

def add_venv_sitepackages_to_sys_path(py: Path):
    """Prepend the venv's site-packages to this (parent) interpreter's sys.path."""
    cmd = [
        str(py), "-c",
        "import site, json; print(json.dumps((site.getsitepackages() if hasattr(site,'getsitepackages') else []) + [site.getusersitepackages()]))"
    ]
    out = subprocess.check_output(cmd, text=True).strip()
    for p in json.loads(out):
        if p and os.path.isdir(p):
            if p not in sys.path:
                sys.path.insert(0, p)
    print("[mcp-bootstrap] sys.path extended with venv site-packages", flush=True)

# ---------- server process ----------
def run_server(
    py: Path,
    module: str | None,
    server_path: Path | None,
    server_args: list[str] | None = None,
    extra_env: dict[str, str] | None = None,
):
    server_args = _strip_dashdash(server_args)
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)

    if module:
        cmd = [str(py), "-m", module]
        if server_args:
            cmd.extend(server_args)
        return subprocess.Popen(cmd, cwd=str(ROOT), env=env)

    sp = str(server_path or resolve_server_path(None))
    if server_args and len(server_args) > 0:
        # pass through args
        cmd = [str(py), sp] + server_args
        return subprocess.Popen(cmd, cwd=str(ROOT), env=env)

    # no args: inject empty arg so scripts that read sys.argv[1] don't crash
    shim = (
        "import os,sys,runpy; "
        f"sp={str(server_path or resolve_server_path(None))!r}; "
        "sd=os.path.dirname(sp) or '.'; "
        "sys.path.insert(0, sd); "
        "sys.argv=[sp, '']; "
        "runpy.run_path(sp, run_name='__main__')"
    )
    cmd = [str(py), "-c", shim]
    return subprocess.Popen(cmd, cwd=str(ROOT), env=env)

# ---------- hot reload ----------
def hot_loop(
    py: Path,
    module: str | None,
    server_path: Path | None,
    debounce_ms: int,
    server_args: list[str],
) -> None:
    add_venv_sitepackages_to_sys_path(py)

    try:
        from watchfiles import DefaultFilter, awatch  # type: ignore
        use_watchfiles = True
    except Exception as e:
        print(f"[mcp-bootstrap] WARNING: watchfiles import failed ({e}); falling back to polling.", flush=True)
        use_watchfiles = False

    child = run_server(py, module, server_path, server_args=server_args)
    last_restart = 0.0

    if use_watchfiles:
        from watchfiles import DefaultFilter, awatch  # re-import after sys.path tweak

        class Filter(DefaultFilter):  # type: ignore[misc]
            def __call__(self, change, path: str) -> bool:  # type: ignore[override]
                p = Path(path)
                if ".venv" in p.parts or "__pycache__" in p.parts or p.suffix in (".pyc", ".pyo"):
                    return False
                return super().__call__(change, path)

        print(f"[mcp-bootstrap] 🔧 hot-reload watching: {MCP_DIR}", flush=True)

        import asyncio
        async def _loop():
            nonlocal child, last_restart
            async for _changes in awatch(MCP_DIR, debounce=int(debounce_ms), watch_filter=Filter()):
                now = time.time()
                if now - last_restart < 0.3:
                    continue
                last_restart = now
                print("[mcp-bootstrap] 🔄 Changes detected -> restarting server…", flush=True)

                if child and child.poll() is None:
                    child.send_signal(signal.SIGTERM)
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()

                child = run_server(py, module, server_path, server_args=server_args)
                print("[mcp-bootstrap] ✅ Server restarted.", flush=True)

        try:
            asyncio.run(_loop())
        finally:
            if child and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
        return

    # ---- polling fallback ----
    print("[mcp-bootstrap] ⏱️ polling for changes every 0.5s", flush=True)

    def snapshot_mtimes(root: Path) -> dict[Path, int]:
        mtimes: dict[Path, int] = {}
        for p in root.rglob("*.py"):
            if ".venv" in p.parts or "__pycache__" in p.parts:
                continue
            try:
                mtimes[p] = p.stat().st_mtime_ns
            except FileNotFoundError:
                pass
        return mtimes

    state = snapshot_mtimes(MCP_DIR)
    try:
        while True:
            time.sleep(0.5)
            new_state = snapshot_mtimes(MCP_DIR)
            if any(new_state.get(p) != state.get(p) for p in set(state) | set(new_state)):
                print("[mcp-bootstrap] 🔄 Changes detected -> restarting server…", flush=True)
                if child and child.poll() is None:
                    child.send_signal(signal.SIGTERM)
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
                child = run_server(py, module, server_path, server_args=server_args)
                print("[mcp-bootstrap] ✅ Server restarted.", flush=True)
                state = new_state
    finally:
        if child and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()

def _strip_dashdash(args: list[str] | None) -> list[str]:
    """
    argparse.REMAINDER keeps the literal '--' if you use it.
    This removes a leading '--' and returns the rest.
    """
    if not args:
        return []
    return args[1:] if args[0] == "--" else args

def main() -> None:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--module", help="Run server as a module (e.g., infra.experimental.mcp.oss_fuzz_server)")
    g.add_argument("--server-path", help="Path to server script (e.g., infra/experimental/mcp/oss_fuzz_server.py)")
    ap.add_argument("--hot", action="store_true", help="Enable hot reload using watchfiles if available")
    ap.add_argument("--debounce-ms", type=int, default=250, help="File change debounce in milliseconds")
    # Everything after '--' gets forwarded to the server (if provided)
    ap.add_argument("server_args", nargs=argparse.REMAINDER, help="Arguments passed to the server after '--'")
    args = ap.parse_args()

    py = ensure_venv()
    ensure_requirements(py, ensure_watchfiles=args.hot)

    # Always run from repo root so relative paths work
    os.chdir(ROOT)

    forward = _strip_dashdash(args.server_args)

    if args.hot:
        # Hot loop supervises and restarts the child; pass server args through
        hot_loop(
            py=py,
            module=args.module,
            server_path=Path(args.server_path) if args.server_path else None,
            debounce_ms=args.debounce_ms,
            server_args=forward,
        )
        return

    # --- Non-hot path: exec directly into the server ---
    if args.module:
        # Module case: just exec with whatever args were provided
        os.execv(str(py), [str(py), "-m", args.module] + forward)

    # Script case: resolve the script path
    server = str(resolve_server_path(args.server_path))

    if forward:
        # If args were provided, pass them through
        os.execv(str(py), [str(py), server] + forward)

    # No args provided, but the script may access sys.argv[1]; inject a benign empty arg via a shim
    shim = (
        "import os,sys,runpy; "
        f"sp={server!r}; "
        "sd=os.path.dirname(sp) or '.'; "
        "sys.path.insert(0, sd); "
        "sys.argv=[sp, '']; "
        "runpy.run_path(sp, run_name='__main__')"
    )
    os.execv(str(py), [str(py), "-c", shim])


if __name__ == "__main__":
    main()
