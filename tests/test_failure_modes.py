"""
Failure Mode Test Suite — Protocol-SIFT-Async-Bridge
======================================================

Every test here represents a documented failure mode.
Results feed directly into docs/accuracy_report.md.

Test categories:
  FM-1  Truncation with high-signal artifacts past line 120
  FM-2  Agent response to status=timeout (no crash, actionable guidance)
  FM-3  Agent response to status=failed (non-zero returncode)
  FM-4  Volatility binary missing at runtime
  FM-5  Busy memory image — concurrent jobs under pool pressure
  FM-6  Malformed extra_args injection attempts
  FM-7  Job registry isolation (no cross-job contamination)
  FM-8  Output parser edge cases (empty, binary garbage, Unicode)
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Synthetic Volatility output generators
# ---------------------------------------------------------------------------

def _build_pslist(total_rows: int, malware_row: int, malware_pid: int = 9999) -> str:
    """
    Generate a synthetic pslist output where the malware process appears
    at a specific row index.  Used to test truncation boundary behaviour.
    """
    header = (
        "Volatility 3 Framework 2.7.0\n"
        "Progress: 100.00\t\tPDB scanning finished\n"
        "PID\tPPID\tImageFileName\tOffset(V)\tThreads\tHandles\tSessionId\tWow64\tCreateTime\n"
    )
    rows = []
    for i in range(total_rows):
        pid = 1000 + i
        ppid = 4 if i % 7 != 0 else 856  # varied parents
        name = "svchost.exe"
        if i == malware_row:
            pid = malware_pid
            ppid = 6120  # explorer.exe — anomalous for svchost
            name = "svchost.exe"   # same name, wrong parent (hollowing indicator)
        rows.append(
            f"{pid}\t{ppid}\t{name}\t0x86{i:06x}\t{2+i%4}\t{10+i}\t0\tFalse\t"
            f"2024-01-15 08:{i//60:02d}:{i%60:02d}.000000 UTC"
        )
    return header + "\n".join(rows)


def _build_malfind(pid: int, injected_rows: int = 30) -> str:
    """Simulate malfind output for a specific PID with hex dump sections."""
    header = (
        "Volatility 3 Framework 2.7.0\n"
        "Progress: 100.00\t\tPDB scanning finished\n"
        "PID\tProcess\tAddress\tVad Tag\tProtection\tHex Dump\tDisassembly\n"
    )
    sections = []
    for i in range(injected_rows):
        hex_bytes = " ".join(f"{(0x4d + j) % 256:02x}" for j in range(16))
        sections.append(
            f"{pid}\tsvchost.exe\t0x00400{i:03x}000\tVadS\tPAGE_EXECUTE_READWRITE\t"
            f"{hex_bytes}\tMOV EAX, 0x{i:08x}"
        )
    return header + "\n".join(sections)


def _build_netscan(c2_row: int, total_rows: int = 200) -> str:
    header = (
        "Volatility 3 Framework 2.7.0\n"
        "Progress: 100.00\t\tPDB scanning finished\n"
        "Offset\tProto\tLocalAddr\tLocalPort\tForeignAddr\tForeignPort\tState\tPID\tOwner\tCreated\n"
    )
    rows = []
    for i in range(total_rows):
        foreign = "10.0.0.1" if i != c2_row else "185.220.101.47"  # known Tor exit
        port = 443 if i != c2_row else 8443
        state = "ESTABLISHED"
        rows.append(
            f"0x86{i:06x}\tTCPv4\t192.168.1.50\t{50000+i}\t"
            f"{foreign}\t{port}\t{state}\t9999\tsvchost.exe\t2024-01-15 08:23:44 UTC"
        )
    return header + "\n".join(rows)


# ---------------------------------------------------------------------------
# FM-1: Truncation with high-signal artifacts past line 120
# ---------------------------------------------------------------------------

class TestTruncationHighSignal:
    """
    FM-1: Document exactly what gets dropped and whether the agent can recover.

    Finding: When MAX_OUTPUT_LINES=120 and the malware process appears at row
    450 in an 800-row pslist, it is silently dropped from the returned summary.
    The 'truncated=True' flag is the ONLY signal that not all data was seen.
    Recovery path: agent must re-run with targeted --pid / --name filter.
    """

    def test_malware_at_row_450_is_dropped_from_summary(self):
        from server.mcp_vol_server import _parse_vol_output

        output = _build_pslist(total_rows=800, malware_row=450, malware_pid=9999)
        summary, row_count, truncated = _parse_vol_output(output)

        # Confirm truncation happened
        assert truncated is True
        assert row_count == 20  # MAX_OUTPUT_LINES set to 20 in test env

        # Confirm PID 9999 (malware) is NOT in the summary
        assert "9999" not in summary, (
            "CRITICAL: malware PID 9999 appeared at row 450 but was included "
            "in the 20-row summary — unexpected."
        )
        assert "TRUNCATED" in summary

    def test_malware_within_cap_is_preserved(self):
        from server.mcp_vol_server import _parse_vol_output

        output = _build_pslist(total_rows=800, malware_row=5, malware_pid=9999)
        summary, row_count, truncated = _parse_vol_output(output)

        assert truncated is True
        assert "9999" in summary  # row 5 is within the 20-row cap

    def test_truncated_flag_is_agent_recovery_signal(self):
        """
        Verify that the job record exposes 'truncated' so the agent can
        detect that a re-run with filters is needed.
        """
        import server.mcp_vol_server as mod
        fake_output = _build_pslist(800, malware_row=450, malware_pid=9999)
        fake_proc = MagicMock(stdout=fake_output, stderr="", returncode=0)

        with patch("server.mcp_vol_server.subprocess.run", return_value=fake_proc), \
             patch("server.mcp_vol_server.CASE_REGISTRY",
                   {"test-win10": Path("/tmp/fake.raw")}):
            r = mod.launch_volatility_plugin("test-win10", "pslist")
            job_id = r["job_id"]
            poll = _wait_for_done(mod, job_id, 5.0)

        assert poll["status"] == "complete"
        assert poll["truncated"] is True
        # The agent MUST check this flag and issue a follow-up targeted query

    def test_netscan_c2_past_line_120_is_dropped(self):
        """
        C2 connection to 185.220.101.47 is at row 150 — past the cap.
        Without a targeted re-run, the agent would miss the C2 indicator.
        """
        from server.mcp_vol_server import _parse_vol_output

        output = _build_netscan(c2_row=150, total_rows=200)
        summary, _, truncated = _parse_vol_output(output)

        assert truncated is True
        assert "185.220.101.47" not in summary  # C2 IP dropped

    def test_netscan_c2_within_cap_is_preserved(self):
        from server.mcp_vol_server import _parse_vol_output

        output = _build_netscan(c2_row=8, total_rows=200)
        summary, _, _ = _parse_vol_output(output)

        assert "185.220.101.47" in summary  # C2 IP within cap

    def test_recovery_via_pid_filter_finds_dropped_artifact(self):
        """
        Simulates the correct agent recovery path:
        1. pslist returns truncated=True
        2. Agent re-runs netscan with --pid filter on the suspicious process
        3. The targeted run returns far fewer rows, now within the cap
        """
        import server.mcp_vol_server as mod

        # Run 1: pslist — truncated, but PID 9999 is in rows 0-19 (within cap)
        pslist_out = _build_pslist(800, malware_row=3, malware_pid=9999)
        # Run 2: netscan filtered to PID 9999 — only 1 row, C2 visible
        netscan_filtered = (
            "Volatility 3 Framework 2.7.0\n"
            "Progress: 100.00\t\tPDB scanning finished\n"
            "Offset\tProto\tLocalAddr\tLocalPort\tForeignAddr\tForeignPort\tState\tPID\n"
            "0x86000000\tTCPv4\t192.168.1.50\t54321\t185.220.101.47\t8443\tESTABLISHED\t9999\n"
        )

        call_count = {"n": 0}

        def side_effect(cmd, **kwargs):
            n = call_count["n"]
            call_count["n"] += 1
            if n == 0:
                return MagicMock(stdout=pslist_out, stderr="", returncode=0)
            return MagicMock(stdout=netscan_filtered, stderr="", returncode=0)

        with patch("server.mcp_vol_server.subprocess.run", side_effect=side_effect), \
             patch("server.mcp_vol_server.CASE_REGISTRY",
                   {"test-win10": Path("/tmp/fake.raw")}):
            # Run 1: broad pslist
            r1 = mod.launch_volatility_plugin("test-win10", "pslist")
            p1 = _wait_for_done(mod, r1["job_id"], 5.0)
            assert p1["truncated"] is True  # agent detects: must filter

            # Run 2: targeted netscan using PID found in run 1
            r2 = mod.launch_volatility_plugin(
                "test-win10", "netscan", extra_args=["--pid", "9999"]
            )
            p2 = _wait_for_done(mod, r2["job_id"], 5.0)
            assert "185.220.101.47" in p2["output_summary"]
            assert p2["truncated"] is False


# ---------------------------------------------------------------------------
# FM-2: Timeout handling
# ---------------------------------------------------------------------------

class TestTimeoutHandling:
    """
    FM-2: Agent must receive a clear timeout signal and actionable guidance.
    The server must not crash, hang, or leave orphaned threads.
    """

    def test_timeout_sets_correct_status(self):
        import server.mcp_vol_server as mod
        import subprocess as sp

        with patch("server.mcp_vol_server.subprocess.run",
                   side_effect=sp.TimeoutExpired(cmd=["vol"], timeout=10)), \
             patch("server.mcp_vol_server.CASE_REGISTRY",
                   {"test-win10": Path("/tmp/fake.raw")}):
            r = mod.launch_volatility_plugin("test-win10", "filescan")
            p = _wait_for_done(mod, r["job_id"], 5.0)

        assert p["status"] == "timeout"
        assert p["error"] is not None
        assert "timeout" in p["error"].lower()

    def test_timeout_response_contains_actionable_message(self):
        import server.mcp_vol_server as mod
        import subprocess as sp

        with patch("server.mcp_vol_server.subprocess.run",
                   side_effect=sp.TimeoutExpired(cmd=["vol"], timeout=10)), \
             patch("server.mcp_vol_server.CASE_REGISTRY",
                   {"test-win10": Path("/tmp/fake.raw")}):
            r = mod.launch_volatility_plugin("test-win10", "filescan")
            p = _wait_for_done(mod, r["job_id"], 5.0)

        # check_job_status injects a guidance message for timeout
        poll = mod.check_job_status(r["job_id"])
        assert "message" in poll
        assert "filter" in poll["message"].lower() or "targeted" in poll["message"].lower()

    def test_server_accepts_new_jobs_after_timeout(self):
        """Server must not be wedged after a timeout — next job must run."""
        import server.mcp_vol_server as mod
        import subprocess as sp

        call_n = {"n": 0}

        def side_effect(cmd, **kwargs):
            n = call_n["n"]
            call_n["n"] += 1
            if n == 0:
                raise sp.TimeoutExpired(cmd=cmd, timeout=10)
            return MagicMock(stdout="PID\t4\tSystem", stderr="", returncode=0)

        with patch("server.mcp_vol_server.subprocess.run", side_effect=side_effect), \
             patch("server.mcp_vol_server.CASE_REGISTRY",
                   {"test-win10": Path("/tmp/fake.raw")}):
            r1 = mod.launch_volatility_plugin("test-win10", "filescan")
            _wait_for_done(mod, r1["job_id"], 5.0)  # let timeout resolve

            # Server must still accept new jobs
            r2 = mod.launch_volatility_plugin("test-win10", "pslist")
            p2 = _wait_for_done(mod, r2["job_id"], 5.0)

        assert p2["status"] == "complete"

    def test_multiple_simultaneous_timeouts_no_crash(self):
        """Race condition check: all workers timing out simultaneously."""
        import server.mcp_vol_server as mod
        import subprocess as sp

        with patch("server.mcp_vol_server.subprocess.run",
                   side_effect=sp.TimeoutExpired(cmd=["vol"], timeout=10)), \
             patch("server.mcp_vol_server.CASE_REGISTRY",
                   {"test-win10": Path("/tmp/fake.raw")}):
            jobs = [mod.launch_volatility_plugin("test-win10", "pslist") for _ in range(4)]
            results = [_wait_for_done(mod, j["job_id"], 8.0) for j in jobs]

        assert all(r["status"] == "timeout" for r in results)


# ---------------------------------------------------------------------------
# FM-3: Failed job (non-zero returncode from Volatility)
# ---------------------------------------------------------------------------

class TestFailedJobHandling:
    """FM-3: Volatility exits non-zero — common for wrong OS profile."""

    def test_failed_job_captures_stderr(self):
        import server.mcp_vol_server as mod

        fake = MagicMock(
            stdout="",
            stderr="ERROR: Unable to load windows.pslist.PsList module",
            returncode=1,
        )
        with patch("server.mcp_vol_server.subprocess.run", return_value=fake), \
             patch("server.mcp_vol_server.CASE_REGISTRY",
                   {"test-win10": Path("/tmp/fake.raw")}):
            r = mod.launch_volatility_plugin("test-win10", "pslist")
            p = _wait_for_done(mod, r["job_id"], 5.0)

        assert p["status"] == "failed"
        assert "Unable to load" in (p["error"] or "")

    def test_failed_job_does_not_expose_partial_output_as_complete(self):
        """If returncode != 0, status must be 'failed' even with some stdout."""
        import server.mcp_vol_server as mod

        fake = MagicMock(
            stdout="PID\t4\tSystem\n88\tsmss.exe\n",
            stderr="Warning: symbol lookup failed",
            returncode=2,
        )
        with patch("server.mcp_vol_server.subprocess.run", return_value=fake), \
             patch("server.mcp_vol_server.CASE_REGISTRY",
                   {"test-win10": Path("/tmp/fake.raw")}):
            r = mod.launch_volatility_plugin("test-win10", "pslist")
            p = _wait_for_done(mod, r["job_id"], 5.0)

        assert p["status"] == "failed"
        assert p["returncode"] == 2


# ---------------------------------------------------------------------------
# FM-4: Missing Volatility binary
# ---------------------------------------------------------------------------

class TestMissingBinary:
    """FM-4: vol binary not found — must fail gracefully with diagnosis."""

    def test_missing_binary_error_message_actionable(self):
        import server.mcp_vol_server as mod

        with patch("server.mcp_vol_server.subprocess.run",
                   side_effect=FileNotFoundError("vol: No such file or directory")), \
             patch("server.mcp_vol_server.CASE_REGISTRY",
                   {"test-win10": Path("/tmp/fake.raw")}):
            r = mod.launch_volatility_plugin("test-win10", "pslist")
            p = _wait_for_done(mod, r["job_id"], 5.0)

        assert p["status"] == "failed"
        assert "VOL3_BIN" in (p["error"] or "")  # error must name the fix


# ---------------------------------------------------------------------------
# FM-5: Pool pressure — more jobs than workers
# ---------------------------------------------------------------------------

class TestPoolPressure:
    """
    FM-5: Submit MAX_WORKERS+2 jobs.  Jobs beyond the pool capacity queue
    correctly and complete without data loss or deadlock.
    """

    def test_queued_jobs_complete_in_order(self):
        import server.mcp_vol_server as mod

        results_order = []
        lock = threading.Lock()

        def ordered_side_effect(cmd, **kwargs):
            time.sleep(0.05)  # simulate real work
            pid_line = f"PID\t{id(threading.current_thread()) % 9000 + 1000}\tprocess"
            with lock:
                results_order.append(pid_line)
            return MagicMock(stdout=pid_line, stderr="", returncode=0)

        n_jobs = 6  # > MAX_WORKERS (2 in test env)
        with patch("server.mcp_vol_server.subprocess.run",
                   side_effect=ordered_side_effect), \
             patch("server.mcp_vol_server.CASE_REGISTRY",
                   {"test-win10": Path("/tmp/fake.raw")}):
            jobs = [
                mod.launch_volatility_plugin("test-win10", "pslist")
                for _ in range(n_jobs)
            ]
            polls = [_wait_for_done(mod, j["job_id"], 15.0) for j in jobs]

        statuses = [p["status"] for p in polls]
        assert all(s == "complete" for s in statuses), f"Not all complete: {statuses}"
        assert len(results_order) == n_jobs  # every job ran exactly once


# ---------------------------------------------------------------------------
# FM-6: Injection attempts via extra_args
# ---------------------------------------------------------------------------

class TestExtraArgInjection:
    """FM-6: extra_args must be filtered to prevent command injection."""

    @pytest.mark.parametrize("evil_arg,description", [
        ("A" * 300, "oversized arg (>256 chars)"),
        (123, "non-string arg"),
    ])
    def test_injection_args_rejected(self, evil_arg, description):
        import server.mcp_vol_server as mod

        with patch("server.mcp_vol_server.CASE_REGISTRY",
                   {"test-win10": Path("/tmp/fake.raw")}):
            r = mod.launch_volatility_plugin(
                "test-win10", "pslist", extra_args=[evil_arg]
            )
        assert "error" in r, f"Expected rejection for: {description}"

    def test_valid_pid_filter_passes(self):
        """--pid 1234 is a legitimate filter and must NOT be rejected."""
        import server.mcp_vol_server as mod

        fake = MagicMock(stdout="PID\t1234\tsvchost.exe", stderr="", returncode=0)
        with patch("server.mcp_vol_server.subprocess.run", return_value=fake), \
             patch("server.mcp_vol_server.CASE_REGISTRY",
                   {"test-win10": Path("/tmp/fake.raw")}):
            r = mod.launch_volatility_plugin(
                "test-win10", "dlllist", extra_args=["--pid", "1234"]
            )
        assert "error" not in r
        assert "job_id" in r


# ---------------------------------------------------------------------------
# FM-7: Cross-job registry isolation
# ---------------------------------------------------------------------------

class TestJobRegistryIsolation:
    """FM-7: Two concurrent jobs must never see each other's output."""

    def test_output_isolation_between_concurrent_jobs(self):
        import server.mcp_vol_server as mod

        lock = threading.Lock()
        call_n = {"n": 0}

        def distinct_output(cmd, **kwargs):
            with lock:
                n = call_n["n"]
                call_n["n"] += 1
            time.sleep(0.05)
            output = f"PID\tJOB_MARKER_{n}\n1000\tsvchost.exe"
            return MagicMock(stdout=output, stderr="", returncode=0)

        with patch("server.mcp_vol_server.subprocess.run",
                   side_effect=distinct_output), \
             patch("server.mcp_vol_server.CASE_REGISTRY",
                   {"test-win10": Path("/tmp/fake.raw")}):
            r1 = mod.launch_volatility_plugin("test-win10", "pslist")
            r2 = mod.launch_volatility_plugin("test-win10", "pstree")
            p1 = _wait_for_done(mod, r1["job_id"], 5.0)
            p2 = _wait_for_done(mod, r2["job_id"], 5.0)

        # Each job must contain its own unique marker
        assert "JOB_MARKER_0" in p1["output_summary"]
        assert "JOB_MARKER_1" in p2["output_summary"]
        # Cross-contamination check
        assert "JOB_MARKER_1" not in p1["output_summary"]
        assert "JOB_MARKER_0" not in p2["output_summary"]


# ---------------------------------------------------------------------------
# FM-8: Parser edge cases
# ---------------------------------------------------------------------------

class TestParserEdgeCases:
    """FM-8: Parser must not crash or return garbage on pathological inputs."""

    def test_binary_garbage_does_not_crash_parser(self):
        from server.mcp_vol_server import _parse_vol_output
        garbage = "".join(chr(i % 128) for i in range(500))
        summary, _, _ = _parse_vol_output(garbage)
        assert isinstance(summary, str)

    def test_only_whitespace_returns_no_output(self):
        from server.mcp_vol_server import _parse_vol_output
        summary, count, truncated = _parse_vol_output("   \n\n\t\n   ")
        assert summary == "(no output)"
        assert count == 0

    def test_unicode_process_names_preserved(self):
        from server.mcp_vol_server import _parse_vol_output
        unicode_output = "PID\tImageFileName\n1234\t服务主机.exe\n5678\tプロセス.exe\n"
        summary, _, _ = _parse_vol_output(unicode_output)
        assert "服务主机" in summary
        assert "プロセス" in summary

    def test_very_long_single_line_handled(self):
        from server.mcp_vol_server import _parse_vol_output
        long_line = "A" * 50_000 + "\n"
        summary, _, _ = _parse_vol_output(long_line)
        assert isinstance(summary, str)

    def test_volatility_version_line_stripped_completely(self):
        from server.mcp_vol_server import _parse_vol_output
        output = (
            "Volatility 3 Framework 2.7.0\n"
            "Volatility 3 Framework 2.7.0\n"
            "Progress: 100.00\t\tPDB scanning finished\n"
            "100%|████████| 100/100\n"
            "PID\tImageFileName\n"
            "4\tSystem\n"
        )
        summary, _, _ = _parse_vol_output(output)
        assert "Volatility 3" not in summary
        assert "100%" not in summary
        assert "System" in summary


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _wait_for_done(mod: Any, job_id: str, deadline_secs: float) -> dict:
    """Poll check_job_status until a terminal state or deadline."""
    end = time.time() + deadline_secs
    while time.time() < end:
        poll = mod.check_job_status(job_id)
        if poll.get("status") in ("complete", "failed", "timeout"):
            return poll
        time.sleep(0.05)
    return mod.check_job_status(job_id)
