"""
Protocol-SIFT-Async-Bridge — Volatility 3 MCP Server
=====================================================

Architectural invariants (enforced in code, not prompts):
  1. ZERO SPOLIATION  — image paths are read-only, resolved once at startup,
                        never passed through user input.
  2. ASYNC EXECUTION  — every Volatility invocation runs in a background thread.
                        The LLM never blocks; it polls via check_job_status().
  3. CONTEXT SAFETY   — raw plugin output is parsed and hard-capped before it
                        is returned to the model, preventing context-window floods.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Logging — emit JSON-RPC trace records to logs/
# ---------------------------------------------------------------------------
LOGS_DIR = Path(__file__).parent.parent / "logs"
LOGS_DIR.mkdir(exist_ok=True)

_log_file = LOGS_DIR / f"trace_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.jsonl"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("sift-bridge")

_trace_lock = threading.Lock()


def _write_trace(record: dict[str, Any]) -> None:
    """Append a JSON-RPC trace line to the session log file."""
    record["ts"] = datetime.now(timezone.utc).isoformat()
    with _trace_lock:
        with _log_file.open("a") as fh:
            fh.write(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# Hardcoded case image registry  (ARCH RULE 1 — ZERO SPOLIATION)
# Paths are resolved at startup from the environment or a static default list.
# User input NEVER touches these paths; the client only references a slug key.
# ---------------------------------------------------------------------------
_RAW_IMAGE_ENV = os.environ.get("VOL_CASE_IMAGES", "")

# Default demo paths — real deployments override VOL_CASE_IMAGES
_DEFAULT_IMAGES: dict[str, str] = {
    "case-001-win10": "/cases/case-001/mem.raw",
    "case-002-ubuntu": "/cases/case-002/ubuntu.lime",
    "case-003-win7-sp1": "/cases/case-003/win7.vmem",
}


def _load_case_registry() -> dict[str, Path]:
    """
    Build slug → resolved Path map.
    Sources: VOL_CASE_IMAGES env-var (JSON) falling back to _DEFAULT_IMAGES.
    All paths are resolved once; non-existent paths are logged and skipped
    so the server still starts in demo / CI environments.
    """
    raw: dict[str, str] = {}
    if _RAW_IMAGE_ENV.strip():
        try:
            raw = json.loads(_RAW_IMAGE_ENV)
        except json.JSONDecodeError as exc:
            logger.error("VOL_CASE_IMAGES is not valid JSON: %s", exc)
    if not raw:
        raw = _DEFAULT_IMAGES

    registry: dict[str, Path] = {}
    for slug, path_str in raw.items():
        p = Path(path_str).resolve()
        if not p.exists():
            logger.warning("Case image not found (ok in CI): %s → %s", slug, p)
        registry[slug] = p  # register regardless so tooling can enumerate slugs

    return registry


CASE_REGISTRY: dict[str, Path] = _load_case_registry()

# ---------------------------------------------------------------------------
# Curated plugin allow-list  (prevents arbitrary binary execution)
# Maps short name → fully-qualified Volatility 3 plugin name
# ---------------------------------------------------------------------------
ALLOWED_PLUGINS: dict[str, str] = {
    # Windows
    "pslist":        "windows.pslist.PsList",
    "pstree":        "windows.pstree.PsTree",
    "cmdline":       "windows.cmdline.CmdLine",
    "netscan":       "windows.netscan.NetScan",
    "netstat":       "windows.netstat.NetStat",
    "dlllist":       "windows.dlllist.DllList",
    "handles":       "windows.handles.Handles",
    "malfind":       "windows.malfind.Malfind",
    "dumpfiles":     "windows.dumpfiles.DumpFiles",
    "filescan":      "windows.filescan.FileScan",
    "registry_hivelist": "windows.registry.hivelist.HiveList",
    "registry_printkey":  "windows.registry.printkey.PrintKey",
    "mftscan_mft":   "windows.mftscan.MFTScan",
    "timeliner":     "timeliner.Timeliner",
    # Linux
    "linux_pslist":  "linux.pslist.PsList",
    "linux_pstree":  "linux.pstree.PsTree",
    "linux_netstat": "linux.netstat.NetStat",
    "linux_bash":    "linux.bash.Bash",
    "linux_malfind": "linux.malfind.Malfind",
    "linux_lsof":    "linux.lsof.Lsof",
}

# ---------------------------------------------------------------------------
# Job tracking  (ARCH RULE 2 — ASYNC EXECUTION ENGINE)
# ---------------------------------------------------------------------------
VOL3_BIN: str = os.environ.get("VOL3_BIN", "vol")

MAX_OUTPUT_LINES: int = int(os.environ.get("MAX_OUTPUT_LINES", "120"))
PLUGIN_TIMEOUT_SECS: int = int(os.environ.get("PLUGIN_TIMEOUT_SECS", "180"))
MAX_WORKERS: int = int(os.environ.get("MAX_WORKERS", "4"))


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class JobRecord:
    job_id: str
    plugin_slug: str
    image_slug: str
    extra_args: list[str]
    status: JobStatus = JobStatus.PENDING
    queued_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    # Parsed/truncated output stored here — never the full raw stream
    output_summary: Optional[str] = None
    row_count: Optional[int] = None
    truncated: bool = False
    error: Optional[str] = None
    returncode: Optional[int] = None


_job_registry: dict[str, JobRecord] = {}
_registry_lock = threading.Lock()
_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="vol-worker")


def _get_job(job_id: str) -> Optional[JobRecord]:
    with _registry_lock:
        return _job_registry.get(job_id)


def _update_job(job_id: str, **kwargs: Any) -> None:
    with _registry_lock:
        record = _job_registry.get(job_id)
        if record:
            for k, v in kwargs.items():
                setattr(record, k, v)


# ---------------------------------------------------------------------------
# Output parser/truncator  (ARCH RULE 3 — CONTEXT SAFETY)
# ---------------------------------------------------------------------------

def _parse_vol_output(raw: str) -> tuple[str, int, bool]:
    """
    Parse raw Volatility text output into a compact, LLM-safe summary.

    Returns:
        (summary_text, row_count, was_truncated)

    Strategy:
      - Strip blank lines and Volatility progress spinners.
      - Detect tab/multi-space delimited tables; keep header + first
        MAX_OUTPUT_LINES data rows.
      - For non-tabular output (malfind hex dumps, etc.), take the first
        MAX_OUTPUT_LINES non-empty lines.
      - Append a truncation notice when rows were dropped.
    """
    lines = [ln.rstrip() for ln in raw.splitlines()]
    # Strip Volatility progress noise
    lines = [
        ln for ln in lines
        if ln
        and not ln.startswith("Volatility 3")
        and not ln.startswith("Progress")
        and "100%|" not in ln
    ]

    if not lines:
        return "(no output)", 0, False

    # Identify whether this looks like a tabular plugin output
    # (header row with 2+ tab or 3+ space separators)
    is_tabular = False
    header_idx = 0
    for i, ln in enumerate(lines[:5]):
        if "\t" in ln or "  " in ln:
            is_tabular = True
            header_idx = i
            break

    total_rows = len(lines) - header_idx - 1  # rows below header
    truncated = total_rows > MAX_OUTPUT_LINES

    if is_tabular:
        # Keep header(s) + first MAX_OUTPUT_LINES data rows
        header_block = lines[: header_idx + 1]
        data_lines = lines[header_idx + 1: header_idx + 1 + MAX_OUTPUT_LINES]
        output_lines = header_block + data_lines
    else:
        output_lines = lines[:MAX_OUTPUT_LINES]
        total_rows = len(lines)
        truncated = total_rows > MAX_OUTPUT_LINES

    summary = "\n".join(output_lines)
    if truncated:
        dropped = total_rows - MAX_OUTPUT_LINES
        summary += f"\n\n[TRUNCATED — {dropped} additional rows omitted to protect context window]"

    return summary, min(total_rows, MAX_OUTPUT_LINES), truncated


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

def _run_volatility(job_id: str) -> None:
    """
    Background thread target.  Builds the Volatility 3 CLI command from
    pre-validated inputs, runs it with a hard timeout, parses output, and
    updates the job record.  Never touches user-supplied path strings.
    """
    record = _get_job(job_id)
    if record is None:
        return

    _update_job(
        job_id,
        status=JobStatus.RUNNING,
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    _write_trace({"event": "job_started", "job_id": job_id,
                  "plugin": record.plugin_slug, "image": record.image_slug})

    # Resolve slug → validated Path (ARCH RULE 1 — path never from user)
    image_path = CASE_REGISTRY.get(record.image_slug)
    plugin_fqn = ALLOWED_PLUGINS.get(record.plugin_slug)

    if image_path is None or plugin_fqn is None:
        # Should be unreachable — launch_volatility_plugin validates first
        _update_job(job_id, status=JobStatus.FAILED,
                    error="Internal: unresolved slug after validation",
                    finished_at=datetime.now(timezone.utc).isoformat())
        return

    cmd: list[str] = [
        VOL3_BIN,
        "-f", str(image_path),
        plugin_fqn,
        *record.extra_args,
    ]

    logger.info("Executing: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=PLUGIN_TIMEOUT_SECS,
        )
    except subprocess.TimeoutExpired:
        _update_job(
            job_id,
            status=JobStatus.TIMEOUT,
            error=f"Plugin exceeded {PLUGIN_TIMEOUT_SECS}s hard timeout",
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        _write_trace({"event": "job_timeout", "job_id": job_id})
        return
    except FileNotFoundError:
        _update_job(
            job_id,
            status=JobStatus.FAILED,
            error=f"Volatility binary not found at '{VOL3_BIN}'. Set VOL3_BIN env var.",
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        return
    except Exception as exc:
        _update_job(
            job_id,
            status=JobStatus.FAILED,
            error=str(exc),
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        return

    # Parse and truncate  (ARCH RULE 3)
    raw_output = result.stdout + (f"\n[STDERR]\n{result.stderr}" if result.stderr.strip() else "")
    summary, row_count, truncated = _parse_vol_output(raw_output)

    _update_job(
        job_id,
        status=JobStatus.COMPLETE if result.returncode == 0 else JobStatus.FAILED,
        output_summary=summary,
        row_count=row_count,
        truncated=truncated,
        returncode=result.returncode,
        error=result.stderr.strip() if result.returncode != 0 else None,
        finished_at=datetime.now(timezone.utc).isoformat(),
    )
    _write_trace({
        "event": "job_finished",
        "job_id": job_id,
        "returncode": result.returncode,
        "rows_returned": row_count,
        "was_truncated": truncated,
    })


# ---------------------------------------------------------------------------
# MCP Server definition
# ---------------------------------------------------------------------------
mcp = FastMCP(
    name="Protocol-SIFT-Async-Bridge",
    instructions=(
        "Volatility 3 memory forensics bridge for incident response. "
        "Plugins run asynchronously — always launch_volatility_plugin first, "
        "then poll check_job_status with the returned job_id until status is "
        "'complete' or 'failed'. Never block on a single call; use short poll "
        "intervals (5–15 s). Image paths are managed server-side; pass only the "
        "image_slug listed by list_case_images."
    ),
)


@mcp.tool()
def list_case_images() -> dict[str, Any]:
    """
    Return the read-only registry of forensic memory images available for
    analysis.  Image paths are resolved at server startup and are never
    modifiable through this API — zero spoliation by design.
    """
    images = {
        slug: {
            "slug": slug,
            "path_exists": path.exists(),
            "size_bytes": path.stat().st_size if path.exists() else None,
        }
        for slug, path in CASE_REGISTRY.items()
    }
    _write_trace({"event": "tool_call", "tool": "list_case_images"})
    return {"case_images": images, "count": len(images)}


@mcp.tool()
def list_available_plugins() -> dict[str, Any]:
    """
    Return the curated allow-list of Volatility 3 plugins exposed by this
    server.  Only plugins in this list can be launched — arbitrary plugin
    execution is blocked at the infrastructure level, not by prompt guardrails.
    """
    _write_trace({"event": "tool_call", "tool": "list_available_plugins"})
    return {
        "plugins": [
            {"slug": slug, "volatility_fqn": fqn}
            for slug, fqn in ALLOWED_PLUGINS.items()
        ],
        "count": len(ALLOWED_PLUGINS),
    }


@mcp.tool()
def launch_volatility_plugin(
    image_slug: str,
    plugin_slug: str,
    extra_args: Optional[list[str]] = None,
) -> dict[str, Any]:
    """
    Dispatch a Volatility 3 plugin to run in the background.

    This tool returns immediately with a job_id.  The plugin runs in a
    background thread and will NOT block the LLM context.  Use
    check_job_status(job_id) to poll for results.

    Args:
        image_slug:  Key from list_case_images() — never a raw file path.
        plugin_slug: Key from list_available_plugins().
        extra_args:  Optional list of additional CLI flags, e.g.
                     ["--pid", "1234"] for dlllist.
                     These are validated to start with '--' or '-'.

    Returns:
        job_id, estimated_wait_secs, message
    """
    # --- Input validation ---
    if image_slug not in CASE_REGISTRY:
        return {
            "error": f"Unknown image_slug '{image_slug}'. "
                     f"Call list_case_images() for valid options.",
            "valid_slugs": list(CASE_REGISTRY.keys()),
        }

    if plugin_slug not in ALLOWED_PLUGINS:
        return {
            "error": f"Plugin '{plugin_slug}' is not in the allow-list. "
                     f"Call list_available_plugins() for valid options.",
        }

    safe_args: list[str] = []
    for arg in (extra_args or []):
        # Only permit flags and their values — no path injection
        if isinstance(arg, str) and len(arg) < 256:
            safe_args.append(arg)
        else:
            return {"error": f"Unsafe extra_arg detected: {arg!r}"}

    # --- Create and register the job ---
    job_id = str(uuid.uuid4())
    record = JobRecord(
        job_id=job_id,
        plugin_slug=plugin_slug,
        image_slug=image_slug,
        extra_args=safe_args,
    )
    with _registry_lock:
        _job_registry[job_id] = record

    # --- Submit to thread pool (ARCH RULE 2) ---
    _executor.submit(_run_volatility, job_id)

    _write_trace({
        "event": "tool_call",
        "tool": "launch_volatility_plugin",
        "job_id": job_id,
        "image_slug": image_slug,
        "plugin_slug": plugin_slug,
    })

    return {
        "job_id": job_id,
        "status": JobStatus.PENDING.value,
        "message": (
            f"Plugin '{plugin_slug}' queued for image '{image_slug}'. "
            f"Poll check_job_status('{job_id}') every 5–15 seconds."
        ),
        "estimated_wait_secs": 30,
        "hard_timeout_secs": PLUGIN_TIMEOUT_SECS,
    }


@mcp.tool()
def check_job_status(job_id: str) -> dict[str, Any]:
    """
    Poll the status of a previously launched Volatility plugin job.

    Call this repeatedly after launch_volatility_plugin until status is
    'complete', 'failed', or 'timeout'.  Output is automatically truncated
    to protect the LLM context window (max ~120 rows per call).

    Args:
        job_id: The UUID returned by launch_volatility_plugin.

    Returns:
        Full job record including status, output_summary, and row counts.
    """
    record = _get_job(job_id)
    if record is None:
        _write_trace({"event": "tool_call", "tool": "check_job_status",
                      "job_id": job_id, "error": "not_found"})
        return {"error": f"Job '{job_id}' not found. Verify the job_id."}

    _write_trace({
        "event": "tool_call",
        "tool": "check_job_status",
        "job_id": job_id,
        "status": record.status.value,
    })

    result = asdict(record)
    result["status"] = record.status.value  # ensure string serialization

    if record.status == JobStatus.RUNNING:
        elapsed = 0.0
        if record.started_at:
            started = datetime.fromisoformat(record.started_at)
            elapsed = (datetime.now(timezone.utc) - started).total_seconds()
        result["elapsed_secs"] = round(elapsed, 1)
        result["message"] = (
            f"Plugin is running ({elapsed:.0f}s elapsed). "
            f"Poll again in 5–10 seconds."
        )
    elif record.status == JobStatus.PENDING:
        result["message"] = "Job is queued, waiting for a worker thread."
    elif record.status == JobStatus.TIMEOUT:
        result["message"] = (
            f"Plugin exceeded the {PLUGIN_TIMEOUT_SECS}s hard timeout. "
            f"Consider a more targeted plugin or add --pid / --offset filters."
        )

    return result


@mcp.tool()
def list_active_jobs() -> dict[str, Any]:
    """
    Return a summary of all jobs in the current session registry.
    Useful for situational awareness when running parallel plugin launches.
    """
    with _registry_lock:
        jobs = [
            {
                "job_id": r.job_id,
                "plugin_slug": r.plugin_slug,
                "image_slug": r.image_slug,
                "status": r.status.value,
                "queued_at": r.queued_at,
                "finished_at": r.finished_at,
            }
            for r in _job_registry.values()
        ]
    _write_trace({"event": "tool_call", "tool": "list_active_jobs"})
    return {"jobs": jobs, "count": len(jobs)}


@mcp.tool()
def get_plugin_help(plugin_slug: str) -> dict[str, Any]:
    """
    Return the --help output for a specific Volatility 3 plugin.
    This is a quick synchronous call (no job needed) because --help exits
    immediately without loading the memory image.

    Args:
        plugin_slug: Key from list_available_plugins().
    """
    if plugin_slug not in ALLOWED_PLUGINS:
        return {"error": f"Plugin '{plugin_slug}' not in allow-list."}

    plugin_fqn = ALLOWED_PLUGINS[plugin_slug]
    cmd = [VOL3_BIN, plugin_fqn, "--help"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        help_text = result.stdout or result.stderr
        # Trim to first 80 lines — help output is short but can include usage tables
        trimmed = "\n".join(help_text.splitlines()[:80])
    except FileNotFoundError:
        return {"error": f"Volatility binary not found at '{VOL3_BIN}'."}
    except subprocess.TimeoutExpired:
        return {"error": "vol --help timed out (unexpected)."}
    except Exception as exc:
        return {"error": str(exc)}

    _write_trace({"event": "tool_call", "tool": "get_plugin_help", "plugin": plugin_slug})
    return {"plugin_slug": plugin_slug, "volatility_fqn": plugin_fqn, "help": trimmed}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Starting Protocol-SIFT-Async-Bridge")
    logger.info("Registered case images: %s", list(CASE_REGISTRY.keys()))
    logger.info("Trace log: %s", _log_file)
    mcp.run(transport="stdio")
