#!/usr/bin/env python3
"""
Protocol-SIFT-Async-Bridge — Pre-Flight Environment Validation
==============================================================

Validates every dependency the server needs before any forensic plugin
is dispatched.  Exit code 0 = ready to run.  Exit code 1 = blocking
errors that will cause runtime failures.

Usage:
    python3 scripts/verify_env.py
    ./scripts/verify_env.py          # after chmod +x

    SIMULATION_MODE=true python3 scripts/verify_env.py
        Marks the Volatility-binary check (3) and image-path check (5) as
        SKIPPED rather than failing/warning when no real binary or memory
        image is present — matches the mocked subprocess layer used by
        scripts/triage_simulation.py. Skipped checks are reported honestly
        in the final tally, never as PASS.

What is checked:
    1.  Python version  (>= 3.11 required)
    2.  All packages listed in requirements.txt
    3.  Volatility 3 binary reachable and executable
    4.  VOL_CASE_IMAGES  — must be valid JSON, not a directory path
        (the server parses this as {"slug": "/abs/path/to/image"})
    5.  Each registered image path — existence + read-access
    6.  VOL3_BIN env var  — warn if unset (falls back to 'vol')
    7.  Logging directory  — write-access verified
    8.  Server entrypoint  — server/mcp_vol_server.py present
    9.  SIFT_BRIDGE_STORAGE — disk output root write-access
    10. Resource governance parameters (MAX_CONCURRENT_FORENSIC_JOBS, PROCESS_MEM_LIMIT_MB)
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ── colour helpers (no external deps) ───────────────────────────────────────
_NO_COLOR = not sys.stdout.isatty() or os.environ.get("NO_COLOR")
_GREEN = "" if _NO_COLOR else "\033[92m"
_RED   = "" if _NO_COLOR else "\033[91m"
_YELLOW= "" if _NO_COLOR else "\033[93m"
_DIM   = "" if _NO_COLOR else "\033[2m"
_BOLD  = "" if _NO_COLOR else "\033[1m"
_RESET = "" if _NO_COLOR else "\033[0m"

# SIMULATION_MODE relaxes checks that require a live Volatility binary or real
# memory images — both unavailable in CI / triage_simulation.py. It does NOT
# mark those checks as PASSED; it marks them SKIPPED so the report stays honest
# about what was actually verified.
SIMULATION_MODE = os.getenv("SIMULATION_MODE", "false").lower() == "true"

_errors   = 0
_warnings = 0
_skipped  = 0


def _ok(msg: str) -> None:
    print(f"{_GREEN}[+]{_RESET} {msg}")


def _fail(msg: str) -> None:
    global _errors
    _errors += 1
    print(f"{_RED}[-]{_RESET} {msg}")


def _warn(msg: str) -> None:
    global _warnings
    _warnings += 1
    print(f"{_YELLOW}[!]{_RESET} {msg}")


def _skip(msg: str) -> None:
    global _skipped
    _skipped += 1
    print(f"{_DIM}[~]{_RESET} {msg} {_DIM}(SIMULATION MODE — not verified){_RESET}")


def _info(msg: str) -> None:
    print(f"{_DIM}    {msg}{_RESET}")


# ── helpers ──────────────────────────────────────────────────────────────────

def _project_root() -> Path:
    """Return the project root regardless of where this script is invoked from."""
    return Path(__file__).resolve().parent.parent


def _parse_version(ver_str: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", ver_str)
    return tuple(int(p) for p in parts[:3]) if parts else (0,)


# ── check functions ──────────────────────────────────────────────────────────

def check_python_version() -> None:
    print(f"\n{_BOLD}[1/10] Python Version{_RESET}")
    major, minor = sys.version_info[:2]
    ver_str = f"{major}.{minor}.{sys.version_info.micro}"
    if (major, minor) >= (3, 11):
        _ok(f"Python {ver_str}  (>= 3.11 required)")
    else:
        _fail(
            f"Python {ver_str} is too old. Upgrade to 3.11+.  "
            f"Current interpreter: {sys.executable}"
        )


def check_packages() -> None:
    print(f"\n{_BOLD}[2/10] Python Package Dependencies{_RESET}")
    req_file = _project_root() / "requirements.txt"
    if not req_file.exists():
        _fail(f"requirements.txt not found at {req_file}")
        return

    # Parse name and minimum version from each line
    missing: list[str] = []
    wrong_ver: list[str] = []

    for raw in req_file.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        # Strip extras like mcp[cli] → mcp, and version specifier
        match = re.match(r"^([A-Za-z0-9_\-]+)(?:\[[^\]]+\])?(?:>=(.+))?", line)
        if not match:
            continue
        pkg_name, min_ver_str = match.group(1), match.group(2)

        # importlib uses underscores; pip uses hyphens
        import_name = pkg_name.replace("-", "_").replace(".", "_").lower()

        # Special-case packages whose import name differs from the dist name
        _IMPORT_MAP = {
            "python_dotenv": "dotenv",
            "pytest_asyncio": "pytest_asyncio",
        }
        import_name = _IMPORT_MAP.get(import_name, import_name)

        spec = importlib.util.find_spec(import_name)
        if spec is None:
            missing.append(pkg_name)
            _fail(f"{pkg_name}  — NOT FOUND")
            continue

        # Attempt version check via importlib.metadata
        installed_ver = None
        try:
            from importlib.metadata import version as pkg_version, PackageNotFoundError
            try:
                installed_ver = pkg_version(pkg_name)
            except PackageNotFoundError:
                installed_ver = pkg_version(pkg_name.replace("-", "_"))
        except Exception:
            pass

        if installed_ver and min_ver_str:
            if _parse_version(installed_ver) < _parse_version(min_ver_str):
                wrong_ver.append(pkg_name)
                _fail(
                    f"{pkg_name}  — installed {installed_ver}, "
                    f"need >= {min_ver_str}"
                )
                continue

        ver_display = f"  (v{installed_ver})" if installed_ver else ""
        _ok(f"{pkg_name}{ver_display}")

    if missing or wrong_ver:
        _info(f"Fix: pip install -r requirements.txt --break-system-packages")


def check_volatility() -> None:
    print(f"\n{_BOLD}[3/10] Volatility 3 Binary{_RESET}")

    # Resolve binary: check VOL3_BIN env var first, then PATH, then common paths
    vol3_bin = os.environ.get("VOL3_BIN", "").strip()
    candidate: str | None = None

    if vol3_bin:
        candidate = shutil.which(vol3_bin) or (vol3_bin if Path(vol3_bin).is_file() else None)
    if not candidate:
        candidate = shutil.which("vol") or shutil.which("vol.py")
    if not candidate and Path("/opt/volatility3/vol.py").exists():
        candidate = "/opt/volatility3/vol.py"

    if not candidate:
        if SIMULATION_MODE:
            _skip("Volatility 3 binary not found.")
            _info("triage_simulation.py mocks the subprocess layer — no real binary required.")
            return
        _fail(
            "Volatility 3 binary not found. Install with: pip install volatility3  "
            "or set VOL3_BIN=/path/to/vol.py"
        )
        _info("Checked: $VOL3_BIN, PATH (vol / vol.py), /opt/volatility3/vol.py")
        return

    # Confirm it actually runs
    try:
        result = subprocess.run(
            [candidate, "--version"],
            capture_output=True, text=True, timeout=10,
        )
        ver_line = (result.stdout or result.stderr or "").splitlines()
        ver_display = ver_line[0].strip() if ver_line else "(version unknown)"
        _ok(f"Volatility 3 at: {candidate}")
        _info(ver_display)
    except subprocess.TimeoutExpired:
        _warn(f"vol --version timed out at {candidate} — binary may be slow or broken")
    except Exception as exc:
        _fail(f"vol binary found at {candidate} but failed to execute: {exc}")


def check_case_images() -> None:
    """
    VOL_CASE_IMAGES must be a JSON object: {"slug": "/abs/path/to/image", ...}

    BUG IN ORIGINAL SPEC: The original verify_env.py treated this variable as
    a directory path and called Path(case_env).is_dir().  That is wrong — the
    server (mcp_vol_server.py line 82) calls json.loads() on this value and
    expects a dict of slug → file path strings.  A directory path string would
    fail json.loads() at startup.  This check is rewritten to match server
    behaviour.
    """
    print(f"\n{_BOLD}[4/10] VOL_CASE_IMAGES — Case Image Registry{_RESET}")

    raw = os.environ.get("VOL_CASE_IMAGES", "").strip()
    if not raw:
        _warn(
            "VOL_CASE_IMAGES is not set.  Server will use demo paths "
            "(all path_exists=false).  Set before live analysis."
        )
        _info(
            'Example: export VOL_CASE_IMAGES=\'{"case-001": "/cases/mem.raw"}\''
        )
        return

    # Validate JSON structure
    try:
        registry: dict = json.loads(raw)
    except json.JSONDecodeError as exc:
        _fail(
            f"VOL_CASE_IMAGES is not valid JSON: {exc}. "
            f"Value received: {raw[:120]!r}"
        )
        _info(
            "The server expects a JSON object, not a directory path.  "
            'Format: \'{"slug-name": "/absolute/path/to/image.raw"}\''
        )
        return

    if not isinstance(registry, dict):
        _fail(f"VOL_CASE_IMAGES JSON must be an object (dict), got: {type(registry).__name__}")
        return

    if len(registry) == 0:
        _warn("VOL_CASE_IMAGES parsed successfully but contains zero entries.")
        return

    _ok(f"VOL_CASE_IMAGES parsed — {len(registry)} slug(s) registered")
    check_case_images._registry = registry  # expose for check 5
    return


check_case_images._registry: dict = {}  # type: ignore[attr-defined]


def check_image_paths() -> None:
    print(f"\n{_BOLD}[5/10] Registered Image Path Accessibility{_RESET}")

    registry: dict = getattr(check_case_images, "_registry", {})
    if not registry:
        _info("No registry to check (VOL_CASE_IMAGES not set or invalid — see check 4).")
        return

    accessible = 0
    sim_skipped = 0
    for slug, path_str in registry.items():
        p = Path(path_str)
        if not p.is_absolute():
            if SIMULATION_MODE:
                _skip(f"  {slug!r}: path is relative ({path_str!r}).")
                sim_skipped += 1
                continue
            _warn(f"  {slug!r}: path is relative ({path_str!r}) — resolve to absolute path")
            continue
        if not p.exists():
            if SIMULATION_MODE:
                _skip(f"  {slug!r}: file not found at {p}.")
                sim_skipped += 1
                continue
            _warn(f"  {slug!r}: file not found at {p}")
            _info("  Path registered but missing — ok in CI, must exist for live analysis")
            continue
        if not os.access(p, os.R_OK):
            _fail(f"  {slug!r}: file exists at {p} but is NOT readable by this user")
            continue
        size_gb = p.stat().st_size / (1024 ** 3)
        _ok(f"  {slug!r}: {p}  ({size_gb:.1f} GB, readable)")
        accessible += 1

    if SIMULATION_MODE and sim_skipped:
        _info("triage_simulation.py does not read these paths — image access not required.")

    if accessible == len(registry):
        _ok(f"All {accessible}/{len(registry)} image(s) accessible")
    elif accessible > 0:
        _warn(f"{accessible}/{len(registry)} image(s) accessible — others missing or unreadable")
    elif not SIMULATION_MODE:
        _warn(f"0/{len(registry)} image(s) accessible — analysis will fail until images are mounted")


def check_vol3_bin_env() -> None:
    print(f"\n{_BOLD}[6/10] VOL3_BIN Environment Variable{_RESET}")

    vol3_bin = os.environ.get("VOL3_BIN", "").strip()
    if vol3_bin:
        resolved = shutil.which(vol3_bin) or (vol3_bin if Path(vol3_bin).exists() else None)
        if resolved:
            _ok(f"VOL3_BIN={vol3_bin!r} → resolved to {resolved}")
        else:
            _fail(
                f"VOL3_BIN={vol3_bin!r} is set but the binary cannot be found. "
                f"Fix the path or unset to fall back to PATH lookup."
            )
    else:
        _warn(
            "VOL3_BIN is not set. Server will search PATH for 'vol'.  "
            "Set VOL3_BIN=/path/to/vol to pin the binary explicitly."
        )


def check_log_directory() -> None:
    print(f"\n{_BOLD}[7/10] Log Directory Write Access{_RESET}")

    log_dir = _project_root() / "logs"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError as exc:
        _fail(f"Cannot create logs/ directory: {exc}")
        return

    probe = log_dir / ".write_probe"
    try:
        probe.write_text("preflight-verification")
        probe.unlink()
        _ok(f"Log directory writable: {log_dir.resolve()}")
    except OSError as exc:
        _fail(f"logs/ exists but is not writable: {exc}")


def check_sift_storage() -> None:
    print(f"\n{_BOLD}[9/10] SIFT_BRIDGE_STORAGE — Disk Output Root{_RESET}")

    raw = os.environ.get("SIFT_BRIDGE_STORAGE", "").strip()
    storage_path = Path(raw) if raw else Path("/tmp/sift_bridge_runtime")

    if not raw:
        _warn(
            f"SIFT_BRIDGE_STORAGE is not set. Defaulting to {storage_path}. "
            f"Set the variable to pin the storage root explicitly."
        )
    else:
        _ok(f"SIFT_BRIDGE_STORAGE={raw!r}")

    try:
        storage_path.mkdir(parents=True, exist_ok=True)
    except PermissionError as exc:
        _fail(f"Cannot create storage root {storage_path}: {exc}")
        return

    probe = storage_path / ".write_probe"
    try:
        probe.write_text("preflight-verification")
        probe.unlink()
        _ok(f"Storage root writable: {storage_path.resolve()}")
    except OSError as exc:
        _fail(f"Storage root exists but is not writable: {exc}")


def check_resource_governance() -> None:
    print(f"\n{_BOLD}[10/10] Resource Governance Parameters{_RESET}")

    max_jobs_raw = os.environ.get("MAX_CONCURRENT_FORENSIC_JOBS", "").strip()
    if max_jobs_raw:
        try:
            max_jobs = int(max_jobs_raw)
            if max_jobs < 1:
                _fail(f"MAX_CONCURRENT_FORENSIC_JOBS={max_jobs_raw!r} must be >= 1")
            else:
                _ok(f"MAX_CONCURRENT_FORENSIC_JOBS={max_jobs}  (worker thread pool cap)")
        except ValueError:
            _fail(f"MAX_CONCURRENT_FORENSIC_JOBS={max_jobs_raw!r} is not a valid integer")
    else:
        _warn(
            "MAX_CONCURRENT_FORENSIC_JOBS is not set. "
            "Defaults to MAX_WORKERS (4). Set to limit concurrent plugin threads."
        )

    mem_raw = os.environ.get("PROCESS_MEM_LIMIT_MB", "").strip()
    if mem_raw:
        try:
            mem_mb = int(mem_raw)
            if mem_mb < 64:
                _warn(f"PROCESS_MEM_LIMIT_MB={mem_mb} is very low (< 64 MB) — plugins may OOM")
            else:
                _ok(f"PROCESS_MEM_LIMIT_MB={mem_mb}  (soft memory budget per analysis session)")
        except ValueError:
            _fail(f"PROCESS_MEM_LIMIT_MB={mem_raw!r} is not a valid integer")
    else:
        _warn(
            "PROCESS_MEM_LIMIT_MB is not set. No memory budget enforced. "
            "Set to a value in MB to enable governance logging."
        )


def check_server_entrypoint() -> None:
    print(f"\n{_BOLD}[8/10] Server Entrypoint{_RESET}")

    server_file = _project_root() / "server" / "mcp_vol_server.py"
    if not server_file.exists():
        _fail(f"server/mcp_vol_server.py not found at {server_file}")
        return
    _ok(f"Server entrypoint present: {server_file.relative_to(_project_root())}")

    # Quick syntax check
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", str(server_file)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        _fail(f"server/mcp_vol_server.py has syntax errors:\n{result.stderr}")
    else:
        _ok("server/mcp_vol_server.py passes syntax check")


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    storage = os.environ.get("SIFT_BRIDGE_STORAGE", "/tmp/sift_bridge_runtime (default)")
    print(
        f"{_BOLD}{'=' * 63}\n"
        f"  Protocol-SIFT-Async-Bridge — Pre-Flight Environment Check\n"
        f"{'=' * 63}{_RESET}\n"
        f"  Python interpreter : {sys.executable}\n"
        f"  Working directory  : {Path.cwd()}\n"
        f"  Project root       : {_project_root()}\n"
        f"  Storage root       : {storage}\n"
        f"  Max forensic jobs  : {os.environ.get('MAX_CONCURRENT_FORENSIC_JOBS', 'unset (default 4)')}\n"
        f"  Mem limit (MB)     : {os.environ.get('PROCESS_MEM_LIMIT_MB', 'unset (unlimited)')}\n"
    )

    check_python_version()
    check_packages()
    check_volatility()
    check_case_images()
    check_image_paths()
    check_vol3_bin_env()
    check_log_directory()
    check_server_entrypoint()
    check_sift_storage()
    check_resource_governance()

    print(f"\n{'─' * 63}")

    if SIMULATION_MODE and _errors == 0:
        passed = 10 - _skipped - _warnings
        print(
            f"{_GREEN}{_BOLD}[+] {passed}/10 CHECKS PASSED, {_skipped} SKIPPED "
            f"(SIMULATION MODE){_RESET}"
            + (f", {_warnings} warning(s)" if _warnings else "")
        )
        print(
            f"{_GREEN}    No live Volatility binary or memory image required — "
            f"ready for scripts/triage_simulation.py{_RESET}"
        )
        sys.exit(0)

    if _errors == 0 and _warnings == 0:
        print(
            f"{_GREEN}{_BOLD}[+] SYSTEM INTEGRITY EXCELLENT.{_RESET}  "
            f"Ready to execute scripts/run_bridge.sh"
        )
        sys.exit(0)
    elif _errors == 0:
        print(
            f"{_YELLOW}{_BOLD}[!] {_warnings} WARNING(S) — {_RESET}"
            f"server will start but live analysis may be degraded. "
            f"Review warnings above."
        )
        print(f"{_YELLOW}    Run: scripts/run_bridge.sh{_RESET}")
        sys.exit(0)
    else:
        print(
            f"{_RED}{_BOLD}[-] {_errors} BLOCKING ERROR(S){_RESET}"
            + (f", {_warnings} warning(s)" if _warnings else "")
            + f".  Resolve issues above before running the server."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
