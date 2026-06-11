"""
Test suite — Protocol-SIFT-Async-Bridge
========================================

Validates the asynchronous job loop without a live Volatility binary or
real memory images.  Uses monkeypatching to inject controlled subprocess
responses so the full background-thread → poll → parse pipeline is exercised.

Run with:
    pytest tests/ -v
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Import the module under test — patch the vol binary + filesystem early
# ---------------------------------------------------------------------------
import importlib
import sys

# Prevent the module from requiring real paths at import time
_FAKE_IMAGES = {
    "test-win10": "/tmp/fake_win10.raw",
    "test-linux": "/tmp/fake_linux.lime",
}
_ENV_PATCH = {
    "VOL_CASE_IMAGES": json.dumps(_FAKE_IMAGES),
    "VOL3_BIN": "vol",
    "MAX_OUTPUT_LINES": "20",
    "PLUGIN_TIMEOUT_SECS": "10",
    "MAX_WORKERS": "2",
}


@pytest.fixture(autouse=True)
def _patch_env(monkeypatch):
    for k, v in _ENV_PATCH.items():
        monkeypatch.setenv(k, v)


# We reload the module inside each test after patching env vars
def _reload_server():
    if "server.mcp_vol_server" in sys.modules:
        del sys.modules["server.mcp_vol_server"]
    import server.mcp_vol_server as mod
    return mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fake_popen(stdout: str = "", returncode: int = 0, stderr: str = "",
                     raise_timeout: bool = False):
    """Return a mock Popen instance with communicate() pre-wired."""
    import subprocess as _sp
    mock = MagicMock()
    mock.pid = 99999
    mock.returncode = returncode
    if raise_timeout:
        mock.communicate.side_effect = [
            _sp.TimeoutExpired(cmd=["vol"], timeout=10),
            ("", ""),
        ]
    else:
        mock.communicate.return_value = (stdout, stderr)
    return mock


FAKE_PSLIST_OUTPUT = """\
Volatility 3 Framework 2.7.0
Progress:  100.00		PDB scanning finished
PID\tPPID\tImageFileName\tOffset(V)\tThreads\tHandles\tSessionId\tWow64\tCreateTime\tExitTime\tFile output
4\t0\tSystem\t0x820480a0\t88\t462\tN/A\tFalse\t2024-01-01 10:00:00.000000\t\tDisabled
88\t4\tsmss.exe\t0x860d0348\t2\t21\tN/A\tFalse\t2024-01-01 10:00:01.000000\t\tDisabled
""" + "\n".join(
    f"{1000+i}\t4\tprocess{i}.exe\t0x86{i:06x}\t2\t10\t0\tFalse\t2024-01-01 10:00:02.000000\t\tDisabled"
    for i in range(50)  # 50 rows to test truncation
)


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

class TestOutputParser:
    """Tests for _parse_vol_output without any subprocess involvement."""

    def test_tabular_output_truncated_at_max_lines(self):
        from server.mcp_vol_server import _parse_vol_output
        summary, row_count, truncated = _parse_vol_output(FAKE_PSLIST_OUTPUT)
        assert truncated is True
        assert row_count == 20  # MAX_OUTPUT_LINES from env patch
        assert "TRUNCATED" in summary

    def test_empty_output_handled(self):
        from server.mcp_vol_server import _parse_vol_output
        summary, row_count, truncated = _parse_vol_output("")
        assert summary == "(no output)"
        assert row_count == 0
        assert truncated is False

    def test_progress_noise_stripped(self):
        from server.mcp_vol_server import _parse_vol_output
        noisy = (
            "Volatility 3 Framework 2.7.0\n"
            "Progress: 100.00\t\tPDB scanning finished\n"
            "PID\tImageFileName\n"
            "4\tSystem\n"
        )
        summary, _, _ = _parse_vol_output(noisy)
        assert "Volatility 3" not in summary
        assert "Progress" not in summary
        assert "System" in summary

    def test_non_tabular_output_capped(self):
        from server.mcp_vol_server import _parse_vol_output
        long_text = "\n".join(f"hex line {i}: deadbeef" for i in range(100))
        summary, row_count, truncated = _parse_vol_output(long_text)
        assert truncated is True
        assert row_count == 20

    def test_short_output_not_truncated(self):
        from server.mcp_vol_server import _parse_vol_output
        short = "PID\tImageFileName\n4\tSystem\n88\tsmss.exe\n"
        summary, row_count, truncated = _parse_vol_output(short)
        assert truncated is False
        assert "System" in summary


class TestCaseRegistry:
    """Validates that the slug registry is built from env vars, not user input."""

    def test_registry_populated_from_env(self):
        import server.mcp_vol_server as mod
        assert "test-win10" in mod.CASE_REGISTRY
        assert "test-linux" in mod.CASE_REGISTRY

    def test_registry_paths_are_path_objects(self):
        import server.mcp_vol_server as mod
        for slug, path in mod.CASE_REGISTRY.items():
            assert isinstance(path, Path), f"Slug '{slug}' has non-Path value"

    def test_user_cannot_inject_path_via_launch(self):
        """Passing an unknown slug must be rejected — never treated as a path."""
        import server.mcp_vol_server as mod
        result = mod.launch_volatility_plugin(
            image_slug="/etc/passwd",  # injection attempt
            plugin_slug="pslist",
        )
        assert "error" in result
        assert "/etc/passwd" not in str(mod.CASE_REGISTRY.values())


class TestPluginAllowList:
    """Ensures only approved plugins can be executed."""

    def test_unknown_plugin_rejected(self):
        import server.mcp_vol_server as mod
        result = mod.launch_volatility_plugin(
            image_slug="test-win10",
            plugin_slug="../../bin/bash",  # traversal attempt
        )
        assert "error" in result

    def test_all_listed_plugins_are_in_allow_list(self):
        import server.mcp_vol_server as mod
        result = mod.list_available_plugins()
        slugs = {p["slug"] for p in result["plugins"]}
        assert "pslist" in slugs
        assert "malfind" in slugs

    def test_extra_args_length_capped(self):
        import server.mcp_vol_server as mod
        evil_arg = "A" * 300  # exceeds 256-char limit
        result = mod.launch_volatility_plugin(
            image_slug="test-win10",
            plugin_slug="pslist",
            extra_args=[evil_arg],
        )
        assert "error" in result


class TestAsyncJobLoop:
    """
    End-to-end test of the background thread → poll → parse pipeline.
    subprocess.run is patched so no real Volatility binary is required.
    """

    def test_job_lifecycle_complete(self):
        """Full round-trip: launch → PENDING → RUNNING → COMPLETE."""
        import server.mcp_vol_server as mod

        fake_proc = _make_fake_popen(stdout=FAKE_PSLIST_OUTPUT, returncode=0)

        with patch("server.mcp_vol_server.subprocess.Popen", return_value=fake_proc), \
             patch("server.mcp_vol_server.CASE_REGISTRY", {
                 "test-win10": Path("/tmp/fake_win10.raw")
             }):
            # Launch
            launch_result = mod.launch_volatility_plugin(
                image_slug="test-win10",
                plugin_slug="pslist",
            )
            assert "job_id" in launch_result
            job_id = launch_result["job_id"]
            assert launch_result["status"] == "pending"

            # Poll until done (max 5 s)
            deadline = time.time() + 5
            final_status = None
            while time.time() < deadline:
                poll = mod.check_job_status(job_id)
                final_status = poll["status"]
                if final_status in ("complete", "failed", "timeout"):
                    break
                time.sleep(0.1)

            assert final_status == "complete", f"Expected complete, got: {final_status}"
            assert poll["output_summary"] is not None
            assert poll["row_count"] is not None
            assert poll["truncated"] is True  # 50 rows > MAX_OUTPUT_LINES=20

    def test_job_fails_on_nonzero_returncode(self):
        """Volatility returning non-zero should set status=failed."""
        import server.mcp_vol_server as mod

        fake_proc = _make_fake_popen(
            stdout="",
            stderr="Error: unsupported profile",
            returncode=1,
        )
        with patch("server.mcp_vol_server.subprocess.Popen", return_value=fake_proc), \
             patch("server.mcp_vol_server.CASE_REGISTRY", {
                 "test-win10": Path("/tmp/fake_win10.raw")
             }):
            result = mod.launch_volatility_plugin("test-win10", "pslist")
            job_id = result["job_id"]

            deadline = time.time() + 5
            while time.time() < deadline:
                poll = mod.check_job_status(job_id)
                if poll["status"] in ("complete", "failed", "timeout"):
                    break
                time.sleep(0.1)

            assert poll["status"] == "failed"
            assert poll["error"] is not None

    def test_job_timeout_sets_timeout_status(self):
        """subprocess.TimeoutExpired must map to JobStatus.TIMEOUT."""
        import server.mcp_vol_server as mod
        import subprocess as sp

        with patch("server.mcp_vol_server.subprocess.Popen",
                   return_value=_make_fake_popen(raise_timeout=True)), \
             patch("server.mcp_vol_server.CASE_REGISTRY", {
                 "test-win10": Path("/tmp/fake_win10.raw")
             }):
            result = mod.launch_volatility_plugin("test-win10", "pslist")
            job_id = result["job_id"]

            deadline = time.time() + 5
            while time.time() < deadline:
                poll = mod.check_job_status(job_id)
                if poll["status"] in ("complete", "failed", "timeout"):
                    break
                time.sleep(0.1)

            assert poll["status"] == "timeout"

    def test_parallel_jobs_tracked_independently(self):
        """Two concurrent jobs must not interfere with each other."""
        import server.mcp_vol_server as mod

        call_count = {"n": 0}
        lock = threading.Lock()

        def slow_then_fast(cmd, **kwargs):
            with lock:
                n = call_count["n"]
                call_count["n"] += 1
            proc = _make_fake_popen(returncode=0)
            if n == 0:
                def slow_comm(**kw):
                    time.sleep(0.3)
                    return ("PID\tImageFileName\n4\tSystem", "")
                proc.communicate.side_effect = slow_comm
            else:
                proc.communicate.return_value = ("PID\tImageFileName\n88\tsmss.exe", "")
            return proc

        with patch("server.mcp_vol_server.subprocess.Popen", side_effect=slow_then_fast), \
             patch("server.mcp_vol_server.CASE_REGISTRY", {
                 "test-win10": Path("/tmp/fake_win10.raw")
             }):
            r1 = mod.launch_volatility_plugin("test-win10", "pslist")
            r2 = mod.launch_volatility_plugin("test-win10", "pstree")
            assert r1["job_id"] != r2["job_id"]

            deadline = time.time() + 5
            while time.time() < deadline:
                p1 = mod.check_job_status(r1["job_id"])
                p2 = mod.check_job_status(r2["job_id"])
                if (p1["status"] in ("complete", "failed") and
                        p2["status"] in ("complete", "failed")):
                    break
                time.sleep(0.1)

            assert p1["status"] == "complete"
            assert p2["status"] == "complete"
            assert "System" in p1["output_summary"]
            assert "smss.exe" in p2["output_summary"]

    def test_check_nonexistent_job_returns_error(self):
        import server.mcp_vol_server as mod
        result = mod.check_job_status("00000000-0000-0000-0000-000000000000")
        assert "error" in result

    def test_list_active_jobs_reflects_launched_jobs(self):
        import server.mcp_vol_server as mod

        fake_proc = _make_fake_popen("PID\t4\tSystem", returncode=0)
        with patch("server.mcp_vol_server.subprocess.Popen", return_value=fake_proc), \
             patch("server.mcp_vol_server.CASE_REGISTRY", {
                 "test-win10": Path("/tmp/fake_win10.raw")
             }):
            r = mod.launch_volatility_plugin("test-win10", "pslist")
            job_id = r["job_id"]
            active = mod.list_active_jobs()
            ids = [j["job_id"] for j in active["jobs"]]
            assert job_id in ids


class TestPagingTool:
    """
    Validates read_job_output_page — the iterative context feed that lets
    the agent page past the MAX_OUTPUT_LINES truncation ceiling without
    rerunning the plugin or flooding the context window.
    """

    @staticmethod
    def _build_large_pslist(n_rows: int) -> str:
        header = "PID\tPPID\tImageFileName\tOffset(V)\tThreads\tHandles"
        rows = "\n".join(
            f"{1000 + i}\t4\tproc{i}.exe\t0x{i:08x}\t2\t10"
            for i in range(n_rows)
        )
        return f"{header}\n{rows}"

    @staticmethod
    def _complete_job(mod, n_rows: int = 50):
        """Launch a job with n_rows of synthetic pslist and wait for completion."""
        from pathlib import Path
        large_output = TestPagingTool._build_large_pslist(n_rows)
        fake = _make_fake_popen(stdout=large_output, returncode=0)
        with patch("server.mcp_vol_server.subprocess.Popen", return_value=fake), \
             patch("server.mcp_vol_server.CASE_REGISTRY", {"test-win10": Path("/tmp/f.raw")}):
            r = mod.launch_volatility_plugin("test-win10", "pslist")
            job_id = r["job_id"]
            deadline = time.time() + 5
            while time.time() < deadline:
                poll = mod.check_job_status(job_id)
                if poll["status"] in ("complete", "failed", "timeout"):
                    break
                time.sleep(0.05)
            return job_id, poll

    def test_page1_contains_first_rows(self):
        """Page 1 must include rows from the start of the data (proc0, proc1...)."""
        import server.mcp_vol_server as mod
        job_id, poll = self._complete_job(mod, n_rows=50)
        assert poll["status"] == "complete"
        assert poll["truncated"] is True  # 50 rows > MAX_OUTPUT_LINES=20

        page1 = mod.read_job_output_page(job_id, page_number=1)
        assert "error" not in page1
        assert "proc0.exe" in page1["page_content"]
        assert page1["page_number"] == 1
        assert page1["has_more"] is True

    def test_page2_contains_rows_past_truncation_boundary(self):
        """Page 2 must contain rows that were dropped by check_job_status."""
        import server.mcp_vol_server as mod
        job_id, _ = self._complete_job(mod, n_rows=50)

        page1 = mod.read_job_output_page(job_id, page_number=1)
        # Row 20 (proc20) is beyond MAX_OUTPUT_LINES=20, so absent from page 1
        assert "proc20.exe" not in page1["page_content"]

        page2 = mod.read_job_output_page(job_id, page_number=2)
        assert "proc20.exe" in page2["page_content"]
        assert page2["page_number"] == 2

    def test_last_page_has_more_false_and_end_marker(self):
        """Final page must have has_more=False and the END OF FORENSIC OUTPUT marker."""
        import server.mcp_vol_server as mod
        # 50 rows, page_size=20 → total_pages=3
        job_id, _ = self._complete_job(mod, n_rows=50)

        page3 = mod.read_job_output_page(job_id, page_number=3)
        assert page3["has_more"] is False
        assert "END OF FORENSIC OUTPUT" in page3["page_content"]
        assert page3["total_pages"] == 3

    def test_out_of_range_page_returns_error(self):
        """Requesting page beyond total_pages must return an error dict, not crash."""
        import server.mcp_vol_server as mod
        job_id, _ = self._complete_job(mod, n_rows=50)

        result = mod.read_job_output_page(job_id, page_number=99)
        assert "error" in result
        assert "total_pages" in result

    def test_paging_nonexistent_job_returns_error(self):
        """Non-existent job_id must return an error, not a KeyError."""
        import server.mcp_vol_server as mod
        result = mod.read_job_output_page("00000000-0000-0000-0000-000000000000")
        assert "error" in result

    def test_paging_incomplete_job_blocked(self):
        """Paging must be rejected while the job is still pending/running."""
        import server.mcp_vol_server as mod
        from pathlib import Path
        import subprocess as sp

        # Use a slow side-effect so the job stays in running state
        barrier = threading.Event()

        def blocking_popen(*args, **kwargs):
            proc = _make_fake_popen(returncode=0)
            def blocking_comm(**kw):
                barrier.wait(timeout=3)
                return ("PID\t4\tSystem", "")
            proc.communicate.side_effect = blocking_comm
            return proc

        with patch("server.mcp_vol_server.subprocess.Popen", side_effect=blocking_popen), \
             patch("server.mcp_vol_server.CASE_REGISTRY", {"test-win10": Path("/tmp/f.raw")}):
            r = mod.launch_volatility_plugin("test-win10", "pslist")
            job_id = r["job_id"]
            # Give the thread a moment to transition to running
            time.sleep(0.05)
            result = mod.read_job_output_page(job_id)
            assert "error" in result
            assert "terminal" in result["error"].lower() or "complete" in result["error"].lower()
            barrier.set()  # unblock the worker thread

    def test_header_repeated_on_page2(self):
        """Column header must appear on page 2 for self-describing output."""
        import server.mcp_vol_server as mod
        job_id, _ = self._complete_job(mod, n_rows=50)

        page2 = mod.read_job_output_page(job_id, page_number=2)
        assert "PID" in page2["page_content"]
        assert "ImageFileName" in page2["page_content"]

    def test_filter_pattern_restricts_to_matching_rows(self):
        """filter_pattern must narrow pagination to matching rows only."""
        import server.mcp_vol_server as mod
        job_id, _ = self._complete_job(mod, n_rows=50)

        page = mod.read_job_output_page(job_id, page_number=1, filter_pattern="proc37")
        assert "error" not in page
        assert "proc37.exe" in page["page_content"]
        assert "proc1.exe" not in page["page_content"]
        assert page["total_rows"] == 1
        assert page["total_pages"] == 1
        assert page["has_more"] is False
        # Header is still preserved for self-describing output
        assert "PID" in page["page_content"]

    def test_filter_pattern_is_case_insensitive(self):
        """filter_pattern matching must ignore case."""
        import server.mcp_vol_server as mod
        job_id, _ = self._complete_job(mod, n_rows=50)

        page = mod.read_job_output_page(job_id, page_number=1, filter_pattern="PROC37")
        assert "proc37.exe" in page["page_content"]

    def test_filter_pattern_no_matches_returns_empty_page(self):
        """A filter_pattern with zero matches must not crash and report 0 rows."""
        import server.mcp_vol_server as mod
        job_id, _ = self._complete_job(mod, n_rows=50)

        page = mod.read_job_output_page(job_id, page_number=1, filter_pattern="nonexistent-needle")
        assert "error" not in page
        assert page["total_rows"] == 0
        assert page["has_more"] is False


class TestTraceLogging:
    """Validate JSON-RPC traces are written to the logs/ directory."""

    def test_trace_file_created(self, tmp_path, monkeypatch):
        import server.mcp_vol_server as mod
        # Redirect trace writes to a temp file
        trace_records: list[dict] = []
        original_write = mod._write_trace

        def capturing_write(record):
            trace_records.append(record)

        monkeypatch.setattr(mod, "_write_trace", capturing_write)

        mod.list_case_images()
        mod.list_available_plugins()

        events = [r["event"] for r in trace_records]
        assert "tool_call" in events

        monkeypatch.setattr(mod, "_write_trace", original_write)
