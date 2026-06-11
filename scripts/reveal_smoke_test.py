"""
Reveal Smoke Test — Protocol-SIFT-Async-Bridge
===============================================

Quick end-to-end check of the MCP server's async job pipeline against the
CyberDefenders "Reveal" memory image (cases/reveal.dmp), launching pslist,
netscan, and pstree and polling until completion.

Run:
    python3 scripts/reveal_smoke_test.py
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
os.environ["MAX_OUTPUT_LINES"] = "120"
os.environ["PLUGIN_TIMEOUT_SECS"] = "300"
os.environ["MAX_WORKERS"] = "2"
os.environ["MAX_CONCURRENT_FORENSIC_JOBS"] = "2"
os.environ["SIFT_BRIDGE_STORAGE"] = "/tmp/sift_bridge_runtime"

from server import mcp_vol_server as srv  # noqa: E402


def run_plugin(image_slug: str, plugin_slug: str) -> None:
    print(f"\n=== Launching {plugin_slug} on {image_slug} ===")
    launch = srv.launch_volatility_plugin(image_slug=image_slug, plugin_slug=plugin_slug)
    print(launch)
    job_id = launch.get("job_id")
    if not job_id:
        return

    while True:
        status = srv.check_job_status(job_id=job_id)
        print(f"  status={status['status']} truncated={status.get('truncated')}")
        if status["status"] in ("complete", "failed", "timeout"):
            break
        time.sleep(5)

    page = srv.read_job_output_page(job_id=job_id, page_number=1)
    print(f"  has_more={page.get('has_more')}")
    print(page.get("output", "")[:2000])


if __name__ == "__main__":
    print(srv.list_case_images())
    run_plugin("reveal", "pslist")
    run_plugin("reveal", "pstree")
    run_plugin("reveal", "netscan")
