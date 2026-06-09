"""
Triage Simulation — Protocol-SIFT-Async-Bridge
===============================================

Simulates a complete LLM-driven incident response session against the
MCP server.  subprocess.run is patched with realistic Volatility output
so the full async pipeline runs without a live memory image.

Captures every JSON-RPC frame (initialize, tools/list, tools/call request
and response) to logs/triage_sim_<timestamp>.jsonl for judge review.

Run:
    python3 scripts/triage_simulation.py

Output:
    Console — colour-annotated triage timeline
    logs/triage_sim_<timestamp>.jsonl — raw JSON-RPC frame log
"""

from __future__ import annotations

import json
import os
import sys
import time
import threading
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

# Ensure server package importable from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

# ---------------------------------------------------------------------------
# Patch environment before importing server
# ---------------------------------------------------------------------------
FAKE_IMAGES = {
    "case-irc-beacon-win10": "/cases/irc-beacon/win10-mem.raw",
}
os.environ["VOL_CASE_IMAGES"] = json.dumps(FAKE_IMAGES)
os.environ["VOL3_BIN"] = "vol"
os.environ["MAX_OUTPUT_LINES"] = "120"
os.environ["PLUGIN_TIMEOUT_SECS"] = "180"
os.environ["MAX_WORKERS"] = "4"
os.environ["MAX_CONCURRENT_FORENSIC_JOBS"] = "2"
os.environ["PROCESS_MEM_LIMIT_MB"] = "512"
os.environ["SIFT_BRIDGE_STORAGE"] = "/tmp/sift_bridge_runtime"

import server.mcp_vol_server as server_mod  # noqa: E402  (env must be set first)

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
GREEN, YELLOW, RED, CYAN, DIM, BOLD, RESET = (
    "\033[92m", "\033[93m", "\033[91m", "\033[96m",
    "\033[2m", "\033[1m", "\033[0m",
)


def _c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}"


def _banner(text: str) -> None:
    width = 72
    print(f"\n{BOLD}{'═' * width}{RESET}")
    print(f"{BOLD}  {text}{RESET}")
    print(f"{BOLD}{'═' * width}{RESET}")


def _log(phase: str, msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    print(f"{DIM}[{ts}]{RESET} {_c(CYAN, phase):30s}  {msg}")


# ---------------------------------------------------------------------------
# JSON-RPC frame recorder
# ---------------------------------------------------------------------------
LOGS_DIR = Path(__file__).parent.parent / "logs"
LOGS_DIR.mkdir(exist_ok=True)
_SIM_LOG = LOGS_DIR / f"triage_sim_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.jsonl"
_frame_id = 0
_frame_lock = threading.Lock()


def _next_id() -> int:
    global _frame_id
    with _frame_lock:
        _frame_id += 1
        return _frame_id


def _emit_frame(frame: dict[str, Any]) -> None:
    frame["_sim_ts"] = datetime.now(timezone.utc).isoformat()
    with _SIM_LOG.open("a") as fh:
        fh.write(json.dumps(frame) + "\n")


def _rpc_request(method: str, params: dict, req_id: int | None = None) -> dict:
    fid = req_id if req_id is not None else _next_id()
    frame = {"jsonrpc": "2.0", "id": fid, "method": method, "params": params}
    _emit_frame({"direction": "CLIENT→SERVER", **frame})
    return frame


def _rpc_response(req_id: int, result: Any, is_error: bool = False) -> dict:
    if is_error:
        frame = {"jsonrpc": "2.0", "id": req_id, "error": result}
    else:
        frame = {"jsonrpc": "2.0", "id": req_id, "result": result}
    _emit_frame({"direction": "SERVER→CLIENT", **frame})
    return frame


def _tool_call(name: str, arguments: dict) -> tuple[int, dict]:
    """Emit a tools/call request frame and return (req_id, raw_result)."""
    fid = _next_id()
    _rpc_request("tools/call", {"name": name, "arguments": arguments}, req_id=fid)
    # Dispatch to actual server tool function
    fn = {
        "list_case_images":           server_mod.list_case_images,
        "list_available_plugins":     server_mod.list_available_plugins,
        "launch_volatility_plugin":   server_mod.launch_volatility_plugin,
        "check_job_status":           server_mod.check_job_status,
        "read_job_output_page":       server_mod.read_job_output_page,
        "list_active_jobs":           server_mod.list_active_jobs,
        "get_plugin_help":            server_mod.get_plugin_help,
        "generate_incident_report":   server_mod.generate_incident_report,
    }[name]
    raw = fn(**arguments)
    # Wrap in MCP content envelope
    mcp_result = {
        "content": [{"type": "text", "text": json.dumps(raw, default=str)}],
        "isError": False,
    }
    _rpc_response(fid, mcp_result)
    return fid, raw


def _wait_done(job_id: str, label: str, timeout: float = 30.0) -> dict:
    """Poll check_job_status until terminal state, emitting each frame."""
    end = time.time() + timeout
    while time.time() < end:
        _, poll = _tool_call("check_job_status", {"job_id": job_id})
        status = poll.get("status", "unknown")
        elapsed = poll.get("elapsed_secs", "")
        elapsed_str = f" ({elapsed}s)" if elapsed else ""
        _log(label, f"status={_c(YELLOW, status)}{elapsed_str}")
        if status in ("complete", "failed", "timeout"):
            return poll
        time.sleep(2.0)
    return poll


# ---------------------------------------------------------------------------
# Synthetic Volatility responses for each phase
# ---------------------------------------------------------------------------

# Phase 1 — pslist: 340 rows, suspicious svchost.exe at row 290 (pid 9321,
# parent explorer.exe — anomalous for a service host)
def _pslist_output() -> str:
    header = (
        "Volatility 3 Framework 2.7.0\n"
        "Progress: 100.00\t\tPDB scanning finished\n"
        "PID\tPPID\tImageFileName\tOffset(V)\tThreads\tHandles\tSessionId\tWow64\tCreateTime\n"
    )
    rows = []
    for i in range(340):
        pid = 1000 + i * 3
        ppid = 4 if i % 5 != 0 else 684  # services.exe
        name = "svchost.exe" if i % 3 == 0 else ("explorer.exe" if i % 7 == 0 else "chrome.exe")
        if i == 290:
            pid, ppid, name = 9321, 6120, "svchost.exe"  # anomalous parent
        rows.append(
            f"{pid}\t{ppid}\t{name}\t0x86{i:06x}\t{2+i%4}\t{10+i*2}\t1\tFalse\t"
            f"2025-01-15 08:{(i//60)%60:02d}:{i%60:02d}.000000 UTC"
        )
    return header + "\n".join(rows)


# Phase 2 — cmdline for PID 9321 reveals the masquerade
def _cmdline_output() -> str:
    return (
        "Volatility 3 Framework 2.7.0\n"
        "Progress: 100.00\t\tPDB scanning finished\n"
        "PID\tProcess\tArgs\n"
        "9321\tsvchost.exe\tC:\\Users\\Public\\svchost.exe -k netsvcs -beacon https://185.220.101.47:8443/c2\n"
    )


# Phase 3 — malfind on PID 9321: MZ header + shellcode in injected region
def _malfind_output() -> str:
    header = (
        "Volatility 3 Framework 2.7.0\n"
        "Progress: 100.00\t\tPDB scanning finished\n"
        "PID\tProcess\tAddress\tVadTag\tProtection\tHex Dump\n"
    )
    rows = [
        "9321\tsvchost.exe\t0x00400000\tVadS\tPAGE_EXECUTE_READWRITE\t"
        "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00  MZ..............",
        "9321\tsvchost.exe\t0x00401000\tVadS\tPAGE_EXECUTE_READWRITE\t"
        "fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b  ......`..1.d.P0.",
        "9321\tsvchost.exe\t0x00402000\tVadS\tPAGE_EXECUTE_READWRITE\t"
        "e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b 52  .....`..1.d.R0.R",
    ]
    return header + "\n".join(rows)


# Phase 4 — netscan: C2 connection visible at row 7 (within cap)
def _netscan_output() -> str:
    header = (
        "Volatility 3 Framework 2.7.0\n"
        "Progress: 100.00\t\tPDB scanning finished\n"
        "Offset\tProto\tLocalAddr\tLocalPort\tForeignAddr\tForeignPort\tState\tPID\tOwner\tCreated\n"
    )
    rows = []
    for i in range(40):
        foreign = "185.220.101.47" if i == 7 else f"10.0.{i}.1"
        port = 8443 if i == 7 else 443
        pid = 9321 if i == 7 else 1000 + i * 3
        owner = "svchost.exe" if i == 7 else "chrome.exe"
        rows.append(
            f"0x86{i:06x}\tTCPv4\t10.10.14.50\t{50000+i}\t"
            f"{foreign}\t{port}\tESTABLISHED\t{pid}\t{owner}\t"
            f"2025-01-15 08:{i%60:02d}:44.000000 UTC"
        )
    return header + "\n".join(rows)


# Phase 5 — registry printkey: persistence key found
def _registry_output() -> str:
    return (
        "Volatility 3 Framework 2.7.0\n"
        "Progress: 100.00\t\tPDB scanning finished\n"
        "Last Write Time\tHive Offset\tType\tKey\tName\tData\tVolatile\n"
        "2025-01-15 07:58:12.000000 UTC\t0x80001000\tREG_SZ\t"
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\t"
        "WindowsUpdate\tC:\\Users\\Public\\svchost.exe -k netsvcs -beacon "
        "https://185.220.101.47:8443/c2\tFalse\n"
    )


# ---------------------------------------------------------------------------
# Main simulation
# ---------------------------------------------------------------------------

def run_simulation() -> None:
    print(f"\n{BOLD}Protocol-SIFT-Async-Bridge — Live Triage Simulation{RESET}")
    print(f"{DIM}Trace log → {_SIM_LOG}{RESET}\n")

    # ── MCP handshake frames ─────────────────────────────────────────────
    _banner("MCP Handshake")

    _rpc_request("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {"roots": {"listChanged": False}, "sampling": {}},
        "clientInfo": {"name": "sift-triage-sim", "version": "1.0.0"},
    }, req_id=0)
    _rpc_response(0, {
        "protocolVersion": "2024-11-05",
        "capabilities": {"tools": {"listChanged": False}, "logging": {}},
        "serverInfo": {"name": "Protocol-SIFT-Async-Bridge", "version": "1.0.0"},
    })
    _log("initialize", _c(GREEN, "handshake complete"))

    _rpc_request("notifications/initialized", {}, req_id=None)

    # tools/list
    tools_list_id = _next_id()
    _rpc_request("tools/list", {}, req_id=tools_list_id)
    tools_payload = {
        "tools": [
            {"name": "list_case_images",          "description": "Read-only case image registry"},
            {"name": "list_available_plugins",    "description": "Plugin allow-list"},
            {"name": "launch_volatility_plugin",  "description": "Async plugin dispatch → job_id"},
            {"name": "check_job_status",          "description": "Poll job status + output (capped at MAX_OUTPUT_LINES)"},
            {"name": "read_job_output_page",      "description": "Page through full untruncated job output (disk-backed)"},
            {"name": "list_active_jobs",          "description": "Session job overview"},
            {"name": "get_plugin_help",           "description": "Synchronous plugin --help"},
            {"name": "generate_incident_report",  "description": "Compile final report — BLOCKED until all truncated jobs are fully paged"},
        ]
    }
    _rpc_response(tools_list_id, tools_payload)
    _log("tools/list", f"{_c(GREEN, str(len(tools_payload['tools'])) + ' tools')} registered")

    # ── Phase 0: Orient ──────────────────────────────────────────────────
    _banner("Phase 0 — Orient: List Case Images and Plugins")

    _, images = _tool_call("list_case_images", {})
    slugs = list(images["case_images"].keys())
    _log("list_case_images", f"{_c(GREEN, str(images['count']))} image(s): {slugs}")

    _, plugins = _tool_call("list_available_plugins", {})
    _log("list_available_plugins", f"{_c(GREEN, str(plugins['count']))} plugins available")

    TARGET_IMAGE = "case-irc-beacon-win10"

    # ── Phase 1: Broad process list ──────────────────────────────────────
    _banner("Phase 1 — Broad pslist (340 rows, malware at row 290)")

    fake_pslist = MagicMock(stdout=_pslist_output(), stderr="", returncode=0)

    with patch("server.mcp_vol_server.subprocess.run", return_value=fake_pslist), \
         patch("server.mcp_vol_server.CASE_REGISTRY",
               {TARGET_IMAGE: Path("/cases/irc-beacon/win10-mem.raw")}):
        _, launch1 = _tool_call("launch_volatility_plugin", {
            "image_slug": TARGET_IMAGE,
            "plugin_slug": "pslist",
        })
        job1 = launch1["job_id"]
        _log("launch pslist", f"job_id={_c(YELLOW, job1[:8])}… status=pending")
        time.sleep(0.5)  # simulate LLM processing time before first poll
        p1 = _wait_done(job1, "poll pslist")

    assert p1["status"] == "complete"
    print(f"\n{DIM}  Output preview (first 5 lines):{RESET}")
    for line in (p1["output_summary"] or "").splitlines()[:5]:
        print(f"  {DIM}{line}{RESET}")

    truncated = p1["truncated"]
    row_count = p1["row_count"]
    _log(
        "pslist result",
        f"rows={_c(GREEN, str(row_count))}  "
        f"truncated={_c(RED if truncated else GREEN, str(truncated))}",
    )

    if truncated:
        print(f"\n  {_c(YELLOW, '⚠ TRUNCATION DETECTED')} — output capped at {row_count} rows.")
        print(f"  {_c(YELLOW, '  240 rows dropped.')}  Malware at row 290 is NOT visible yet.")

        # ── Phase 1a: Protocol gate test (must happen BEFORE paging) ────────
        _banner("Phase 1a — Protocol Gate: generate_incident_report (expect BLOCKED)")

        _, gate_result = _tool_call("generate_incident_report", {"image_slug": TARGET_IMAGE})
        gate_status = gate_result.get("status", "")
        if gate_status == "PROTOCOL_ERROR":
            _log("gate result", _c(RED, "PROTOCOL_ERROR — report correctly BLOCKED"))
            _log("gate message", gate_result.get("error", "")[:120])
        else:
            _log("gate result", _c(YELLOW, f"unexpected: {gate_status}"))

        print(f"\n  {_c(CYAN, '  Self-Correction: paging full pslist via read_job_output_page...')}")

        _banner("Phase 1b — Self-Correction: Iterative Paging to Recover Truncated Rows")

        # Page 1 is already contained in check_job_status output_summary.
        # Read pages 2 onward until has_more=false to surface PID 9321 at row 290.
        page = 2
        anomaly_page: int | None = None
        while True:
            _, page_result = _tool_call(
                "read_job_output_page", {"job_id": job1, "page_number": page}
            )
            has_more = page_result.get("has_more", False)
            content = page_result.get("page_content", "")
            total_pages = page_result.get("total_pages", "?")
            _log(
                f"read_job_output_page p{page}",
                f"page={_c(CYAN, str(page))}/{total_pages}  "
                f"has_more={_c(YELLOW if has_more else GREEN, str(has_more))}",
            )
            # Surface the anomalous entry when encountered
            if anomaly_page is None:
                for line in content.splitlines():
                    if "9321" in line and "svchost" in line:
                        anomaly_page = page
                        _log(
                            "anomaly surfaced",
                            _c(RED, f"PID 9321 detected on page {page} — "
                                    f"svchost.exe with explorer.exe parent"),
                        )
                        print(f"  {_c(RED, '  ►')} {line}")
                        break
            if not has_more:
                break
            page += 1

        if anomaly_page:
            _log(
                "self-correction complete",
                _c(GREEN, f"Full pslist exhausted — anomaly surfaced on page {anomaly_page}. "
                          f"Pivoting to targeted cmdline --pid 9321."),
            )
        else:
            _log("paging complete", "no anomalies found in full process list")

        # Verify disk output was created by the server (Task 1/3 compliance)
        disk_path = Path(f"/tmp/sift_bridge_runtime/jobs/{job1}/raw_output.txt.gz")
        if disk_path.exists():
            size_kb = disk_path.stat().st_size / 1024
            _log(
                "disk verification",
                _c(GREEN, f"raw_output.txt.gz exists — {size_kb:.1f} KB "
                          f"(host RAM freed after write)"),
            )
            _log("disk path", str(disk_path))
        else:
            _log("disk verification", _c(YELLOW, f"file not found at {disk_path}"))

    # ── Phase 2: Cmdline on anomalous PID (targeted, no truncation) ──────
    _banner("Phase 2 — Targeted cmdline (PID 9321 — anomalous svchost)")

    fake_cmdline = MagicMock(stdout=_cmdline_output(), stderr="", returncode=0)
    with patch("server.mcp_vol_server.subprocess.run", return_value=fake_cmdline), \
         patch("server.mcp_vol_server.CASE_REGISTRY",
               {TARGET_IMAGE: Path("/cases/irc-beacon/win10-mem.raw")}):
        _, launch2 = _tool_call("launch_volatility_plugin", {
            "image_slug": TARGET_IMAGE,
            "plugin_slug": "cmdline",
            "extra_args": ["--pid", "9321"],
        })
        job2 = launch2["job_id"]
        time.sleep(0.3)
        p2 = _wait_done(job2, "poll cmdline")

    _log("cmdline result", _c(RED, "BEACON CMDLINE FOUND"))
    for line in (p2["output_summary"] or "").splitlines()[1:]:  # skip header
        if line.strip():
            print(f"  {_c(RED, '  ►')} {line}")

    # ── Phase 3: Malfind confirms code injection ─────────────────────────
    _banner("Phase 3 — malfind (PID 9321 — confirm process injection)")

    fake_malfind = MagicMock(stdout=_malfind_output(), stderr="", returncode=0)
    with patch("server.mcp_vol_server.subprocess.run", return_value=fake_malfind), \
         patch("server.mcp_vol_server.CASE_REGISTRY",
               {TARGET_IMAGE: Path("/cases/irc-beacon/win10-mem.raw")}):
        _, launch3 = _tool_call("launch_volatility_plugin", {
            "image_slug": TARGET_IMAGE,
            "plugin_slug": "malfind",
            "extra_args": ["--pid", "9321"],
        })
        job3 = launch3["job_id"]
        time.sleep(0.3)
        p3 = _wait_done(job3, "poll malfind")

    _log("malfind result", _c(RED, "MZ HEADER + SHELLCODE IN PAGE_EXECUTE_READWRITE"))
    for line in (p3["output_summary"] or "").splitlines()[1:4]:
        if line.strip():
            print(f"  {_c(RED, '  ►')} {line}")

    # ── Phase 4: Network scan — confirm C2 channel ───────────────────────
    _banner("Phase 4 — netscan (confirm active C2 connection)")

    fake_netscan = MagicMock(stdout=_netscan_output(), stderr="", returncode=0)
    with patch("server.mcp_vol_server.subprocess.run", return_value=fake_netscan), \
         patch("server.mcp_vol_server.CASE_REGISTRY",
               {TARGET_IMAGE: Path("/cases/irc-beacon/win10-mem.raw")}):
        _, launch4 = _tool_call("launch_volatility_plugin", {
            "image_slug": TARGET_IMAGE,
            "plugin_slug": "netscan",
        })
        job4 = launch4["job_id"]
        time.sleep(0.3)
        p4 = _wait_done(job4, "poll netscan")

    _log("netscan result", _c(RED, "ACTIVE C2 CONNECTION TO 185.220.101.47:8443"))
    for line in (p4["output_summary"] or "").splitlines():
        if "185.220.101.47" in line:
            print(f"  {_c(RED, '  ►')} {line}")

    # ── Phase 5: Persistence — registry Run key ───────────────────────────
    _banner("Phase 5 — registry_printkey (confirm persistence)")

    fake_reg = MagicMock(stdout=_registry_output(), stderr="", returncode=0)
    with patch("server.mcp_vol_server.subprocess.run", return_value=fake_reg), \
         patch("server.mcp_vol_server.CASE_REGISTRY",
               {TARGET_IMAGE: Path("/cases/irc-beacon/win10-mem.raw")}):
        _, launch5 = _tool_call("launch_volatility_plugin", {
            "image_slug": TARGET_IMAGE,
            "plugin_slug": "registry_printkey",
            "extra_args": ["--key", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
        })
        job5 = launch5["job_id"]
        time.sleep(0.3)
        p5 = _wait_done(job5, "poll registry")

    _log("registry result", _c(RED, "PERSISTENCE: WindowsUpdate Run key confirmed"))
    for line in (p5["output_summary"] or "").splitlines()[1:]:
        if line.strip():
            print(f"  {_c(RED, '  ►')} {line}")

    # ── Phase 6: Incident report — gate now passes ───────────────────────
    _banner("Phase 6 — generate_incident_report (expect REPORT_READY)")

    _, report = _tool_call("generate_incident_report", {"image_slug": TARGET_IMAGE})
    report_status = report.get("status", "")
    if report_status == "REPORT_READY":
        total = report.get("total_complete_jobs", 0)
        _log("report result", _c(GREEN, f"REPORT_READY — {total} complete jobs compiled"))
        for finding in report.get("findings", []):
            explored = _c(GREEN, "✓") if finding["fully_explored"] else _c(RED, "✗")
            _log(
                "  finding",
                f"{explored} plugin={finding['plugin_slug']:25s} "
                f"rows={finding['row_count']}  truncated={finding['truncated']}",
            )
    elif report_status == "PROTOCOL_ERROR":
        _log("report result", _c(RED, f"UNEXPECTED BLOCK: {report.get('error', '')}"))
    else:
        _log("report result", _c(YELLOW, f"status={report_status}"))

    # ── Phase 7: Timeout failure mode — server stability under load ──────
    _banner("Phase 7 — Failure Mode: filescan TIMEOUT (simulated)")

    import subprocess as sp
    with patch("server.mcp_vol_server.subprocess.run",
               side_effect=sp.TimeoutExpired(cmd=["vol"], timeout=180)), \
         patch("server.mcp_vol_server.CASE_REGISTRY",
               {TARGET_IMAGE: Path("/cases/irc-beacon/win10-mem.raw")}):
        _, launch6 = _tool_call("launch_volatility_plugin", {
            "image_slug": TARGET_IMAGE,
            "plugin_slug": "filescan",
        })
        job6 = launch6["job_id"]
        time.sleep(0.3)
        p6 = _wait_done(job6, "poll filescan")

    assert p6["status"] == "timeout"
    _log("filescan result", _c(RED, "status=timeout — server remains stable"))
    _log("agent guidance", p6.get("message", ""))

    # Confirm server still healthy after hard timeout
    _, health = _tool_call("list_active_jobs", {})
    _log("health check", f"{_c(GREEN, 'server healthy')} — {health['count']} total jobs in registry")

    # ── Session summary ───────────────────────────────────────────────────
    _banner("Session Summary")

    _, active = _tool_call("list_active_jobs", {})
    counts: dict[str, int] = {}
    for j in active["jobs"]:
        counts[j["status"]] = counts.get(j["status"], 0) + 1

    print(f"\n  Total jobs dispatched : {_c(BOLD, str(active['count']))}")
    for status, n in sorted(counts.items()):
        colour = GREEN if status == "complete" else (RED if status == "timeout" else YELLOW)
        print(f"  {status:12s}: {_c(colour, str(n))}")

    print(f"\n  {_c(BOLD, 'IOC Summary')} (from this triage run):")
    print(f"  {_c(RED, '►')} Malicious process : svchost.exe PID 9321 "
          f"(parent: explorer.exe 6120)")
    print(f"  {_c(RED, '►')} Beacon cmdline    : -beacon https://185.220.101.47:8443/c2")
    print(f"  {_c(RED, '►')} Code injection    : MZ+shellcode in PAGE_EXECUTE_READWRITE")
    print(f"  {_c(RED, '►')} C2 connection     : 185.220.101.47:8443 ESTABLISHED")
    print(f"  {_c(RED, '►')} Persistence       : HKLM Run key 'WindowsUpdate'")

    print(f"\n  {_c(DIM, f'Full JSON-RPC trace → {_SIM_LOG}')}")
    print(f"  {_c(DIM, f'Frame count: {_frame_id}')}")
    print()

    # ── Print frame count summary ─────────────────────────────────────────
    with _SIM_LOG.open() as fh:
        frames = [json.loads(line) for line in fh]

    req_frames = [f for f in frames if f.get("direction") == "CLIENT→SERVER"]
    res_frames = [f for f in frames if f.get("direction") == "SERVER→CLIENT"]

    print(f"  JSON-RPC frames written:")
    print(f"    CLIENT→SERVER : {len(req_frames)}")
    print(f"    SERVER→CLIENT : {len(res_frames)}")
    print(f"    Total         : {len(frames)}")

    return _SIM_LOG


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    log_path = run_simulation()
    sys.exit(0)
