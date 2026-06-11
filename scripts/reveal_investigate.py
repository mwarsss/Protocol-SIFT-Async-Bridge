"""
Reveal Investigation — Protocol-SIFT-Async-Bridge
==================================================

Follow-up to scripts/reveal_smoke_test.py: corroborates the WebDAV/rundll32
malware-delivery lead found by pstree+netscan (PID 3692 powershell.exe,
parent PID 4120, spawned PID 2416 net.exe with an ESTABLISHED connection
to 45.9.74.32:8888) using malfind and pslist (for the orphaned PID 4120).

Run:
    python3 scripts/reveal_investigate.py
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
os.environ["MAX_OUTPUT_LINES"] = "200"
os.environ["PLUGIN_TIMEOUT_SECS"] = "300"
os.environ["MAX_WORKERS"] = "2"
os.environ["MAX_CONCURRENT_FORENSIC_JOBS"] = "2"
os.environ["SIFT_BRIDGE_STORAGE"] = "/tmp/sift_bridge_runtime"

from server import mcp_vol_server as srv  # noqa: E402


def run_plugin(image_slug: str, plugin_slug: str, extra_args: list[str] | None = None) -> None:
    print(f"\n=== {plugin_slug} {extra_args or ''} on {image_slug} ===")
    launch = srv.launch_volatility_plugin(
        image_slug=image_slug, plugin_slug=plugin_slug, extra_args=extra_args
    )
    job_id = launch.get("job_id")
    if not job_id:
        print(launch)
        return

    while True:
        status = srv.check_job_status(job_id=job_id)
        if status["status"] in ("complete", "failed", "timeout"):
            break
        time.sleep(5)

    print(f"  status={status['status']} truncated={status.get('truncated')}")

    page_num = 1
    while True:
        page = srv.read_job_output_page(job_id=job_id, page_number=page_num)
        print(page.get("output", ""))
        if not page.get("has_more"):
            break
        page_num += 1


if __name__ == "__main__":
    run_plugin("reveal", "malfind", ["--pid", "3692"])
    run_plugin("reveal", "malfind", ["--pid", "2416"])
    run_plugin("reveal", "pslist", ["--pid", "4120"])
    run_plugin("reveal", "dlllist", ["--pid", "3692"])
