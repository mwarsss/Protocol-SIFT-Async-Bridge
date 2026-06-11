"""
Reveal Demo — Protocol-SIFT-Async-Bridge
=========================================

Phased, narrated incident-response walkthrough against the REAL CyberDefenders
"Reveal" memory image (cases/reveal.dmp) — a Windows 10 host compromised via
a phishing decoy, fileless PowerShell, WebDAV/rundll32 delivery, process
injection, and an active C2 connection.

Mirrors the narrative structure of scripts/triage_simulation.py (banners,
protocol-gate test, self-correction paging, final incident report) but every
job here is a real `vol` invocation against real evidence — nothing mocked.

MAX_OUTPUT_LINES is deliberately set low (30) so the real Reveal outputs
(pslist=111 rows, netscan=81 rows, malfind=92 lines, dlllist=61 lines) trigger
real truncation, exercising the protocol gate and read_job_output_page paging
exactly as they would on a much larger case.

Run:
    python3 scripts/reveal_demo.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

REVEAL_IMAGE = str(Path(__file__).parent.parent / "cases" / "reveal.dmp")

os.environ["VOL_CASE_IMAGES"] = json.dumps({"reveal": REVEAL_IMAGE})
os.environ["VOL3_BIN"] = os.path.expanduser("~/.local/bin/vol")
os.environ["MAX_OUTPUT_LINES"] = "30"
os.environ["PLUGIN_TIMEOUT_SECS"] = "300"
os.environ["MAX_WORKERS"] = "2"
os.environ["MAX_CONCURRENT_FORENSIC_JOBS"] = "2"
os.environ["SIFT_BRIDGE_STORAGE"] = "/tmp/sift_bridge_runtime"

from server import mcp_vol_server as srv  # noqa: E402

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


def _log(label: str, msg: str) -> None:
    print(f"{_c(CYAN, label):30s}  {msg}")


def run_plugin(plugin_slug: str, extra_args: list[str] | None = None):
    label = f"{plugin_slug} {' '.join(extra_args or [])}".strip()
    launch = srv.launch_volatility_plugin(
        image_slug="reveal", plugin_slug=plugin_slug, extra_args=extra_args
    )
    job_id = launch["job_id"]
    _log(label, f"job_id={_c(YELLOW, job_id[:8])}… queued")

    while True:
        status = srv.check_job_status(job_id=job_id)
        if status["status"] in ("complete", "failed", "timeout"):
            break
        time.sleep(5)

    truncated = status.get("truncated")
    _log(
        label,
        f"status={_c(GREEN, status['status'])}  "
        f"rows={status.get('row_count')}  "
        f"truncated={_c(YELLOW if truncated else GREEN, str(truncated))}",
    )
    print(f"\n{DIM}  Output preview:{RESET}")
    for line in (status.get("output_summary") or "").splitlines()[:8]:
        print(f"  {DIM}{line}{RESET}")

    return job_id, status


def page_through(job_id: str, label: str, highlight: str | None = None) -> None:
    page = 1
    while True:
        result = srv.read_job_output_page(job_id=job_id, page_number=page)
        content = result.get("page_content", "")
        has_more = result.get("has_more", False)
        total_pages = result.get("total_pages", "?")
        _log(
            f"{label} page",
            f"{page}/{total_pages}  "
            f"has_more={_c(YELLOW if has_more else GREEN, str(has_more))}",
        )
        if highlight:
            for line in content.splitlines():
                if highlight in line:
                    print(f"  {_c(RED, '►')} {line}")
        if not has_more:
            break
        page += 1


def main() -> None:
    print(f"\n{BOLD}Protocol-SIFT-Async-Bridge — Reveal Live Demo{RESET}")
    print(f"{DIM}Image: {REVEAL_IMAGE}{RESET}")

    # ── Phase 0: Orient ───────────────────────────────────────────────────
    _banner("Phase 0 — Orient: List Case Images and Plugins")

    images = srv.list_case_images()
    _log("list_case_images", f"{images['count']} image(s): {list(images['case_images'].keys())}")

    plugins = srv.list_available_plugins()
    _log("list_available_plugins", f"{plugins['count']} plugins available")

    # ── Phase 1: Broad pslist ────────────────────────────────────────────
    _banner("Phase 1 — Broad pslist")

    job1, p1 = run_plugin("pslist")

    # ── Phase 1a/1b: Protocol gate + self-correction paging ──────────────
    if p1["truncated"]:
        _banner("Phase 1a — Protocol Gate: generate_incident_report (expect BLOCKED)")
        gate = srv.generate_incident_report(image_slug="reveal")
        if gate["status"] == "PROTOCOL_ERROR":
            _log("gate result", _c(RED, "PROTOCOL_ERROR — report correctly BLOCKED"))
            _log("gate message", gate["error"][:160])
        else:
            _log("gate result", _c(YELLOW, f"unexpected: {gate['status']}"))

        _banner("Phase 1b — Self-Correction: Paging Full pslist")
        page_through(job1, "pslist", highlight="4120")

    # ── Phase 2: pstree ────────────────────────────────────────────────────
    _banner("Phase 2 — pstree (process lineage)")

    job2, p2 = run_plugin("pstree")
    if p2["truncated"]:
        page_through(job2, "pstree", highlight="3692")

    # ── Phase 3: cmdline on hidden PowerShell ────────────────────────────
    _banner("Phase 3 — cmdline (PID 3692 — hidden PowerShell)")

    job3, p3 = run_plugin("cmdline", ["--pid", "3692"])
    if p3["truncated"]:
        page_through(job3, "cmdline")

    # ── Phase 4: malfind confirms process injection ─────────────────────
    _banner("Phase 4 — malfind (PID 3692 — confirm process injection)")

    job4, p4 = run_plugin("malfind", ["--pid", "3692"])
    if p4["truncated"]:
        page_through(job4, "malfind")

    # ── Phase 5: netscan confirms C2 channel ─────────────────────────────
    _banner("Phase 5 — netscan (confirm C2 channel)")

    job5, p5 = run_plugin("netscan")
    if p5["truncated"]:
        page_through(job5, "netscan", highlight="45.9.74.32")

    # ── Phase 6: dlllist on hidden PowerShell ────────────────────────────
    _banner("Phase 6 — dlllist (PID 3692 — loaded modules)")

    job6, p6 = run_plugin("dlllist", ["--pid", "3692"])
    if p6["truncated"]:
        page_through(job6, "dlllist")

    # ── Phase 7: Final incident report ───────────────────────────────────
    _banner("Phase 7 — generate_incident_report (expect REPORT_READY)")

    report = srv.generate_incident_report(image_slug="reveal")
    if report["status"] == "REPORT_READY":
        total = report["total_complete_jobs"]
        _log("report result", _c(GREEN, f"REPORT_READY — {total} complete jobs compiled"))
        for finding in report["findings"]:
            explored = _c(GREEN, "✓") if finding["fully_explored"] else _c(RED, "✗")
            _log(
                "  finding",
                f"{explored} plugin={finding['plugin_slug']:20s} "
                f"rows={finding['row_count']}  truncated={finding['truncated']}",
            )
    else:
        _log("report result", _c(RED, f"unexpected: {report['status']} {report.get('error', '')}"))


if __name__ == "__main__":
    main()
