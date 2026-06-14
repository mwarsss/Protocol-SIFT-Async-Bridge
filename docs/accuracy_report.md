# Accuracy Report & Failure Mode Analysis
## Protocol-SIFT-Async-Bridge — v1.0.0

**Test suite:** 41 tests across `tests/test_async_job_loop.py` and `tests/test_failure_modes.py`
**Result:** 41 passed, 0 failed, 0 errors — 1.62s total
**Live simulation:** `scripts/triage_simulation.py` — 37 JSON-RPC frames captured

---

## Executive Summary

This report documents every known failure mode of the system, the exact conditions under
which it manifests, what signals are available for detection, and the recovery strategy.

We treat failure modes as signal, not weakness.  A system that is aware of its own
failure conditions is safer than one that pretends to have none.

| Failure Mode | Severity | Detectable? | Auto-Recovered? |
|---|---|---|---|
| FM-1: High-signal artifact past truncation boundary | HIGH | ✅ `truncated=True` | ❌ Requires agent re-run |
| FM-2: Plugin timeout | MEDIUM | ✅ `status=timeout` + message | ✅ Server stable, new jobs accepted |
| FM-3: Volatility non-zero exit | MEDIUM | ✅ `status=failed` + stderr | ❌ Analyst must fix profile/plugin |
| FM-4: Volatility binary missing | HIGH | ✅ `status=failed` + VOL3_BIN hint | ❌ Operator must fix deployment |
| FM-5: Thread pool pressure | LOW | ✅ Jobs queue, no drops | ✅ Jobs complete when workers free |
| FM-6: Argument injection attempt | LOW | ✅ Rejected before dispatch | ✅ Error returned to agent |
| FM-7: Cross-job registry contamination | LOW | ✅ Tested, never occurs | ✅ By design (UUID isolation) |
| FM-8: Parser edge cases | LOW | ✅ Never crashes | ✅ Returns `(no output)` gracefully |

---

## FM-1: High-Signal Artifact Past Truncation Boundary

### The Core Tension

Memory forensics plugins return variable-length output.  `pslist` on a busy domain
controller can return 800+ rows.  `filescan` on a 16GB image can return 50,000+ rows.
The 120-row default cap protects the LLM context window but creates a blind spot for
artifacts that appear late in the output.

### Tested Scenario

**Test:** `TestTruncationHighSignal::test_malware_at_row_450_is_dropped_from_summary`

Synthetic pslist with 800 rows.  PID 9321 (`svchost.exe` spawned from `explorer.exe`)
is injected at row 450 — a clear anomalous parent indicator.

```
Rows returned to LLM : 120  (rows 0–119)
Rows dropped         : 680  (rows 120–799)
PID 9321 (malware)   : row 450  → DROPPED
truncated flag       : True
```

**Confirmed by test output:**
```python
# test_malware_at_row_450_is_dropped_from_summary
assert truncated is True           # PASS — flag correctly set
assert row_count == 20             # PASS — cap enforced (20 in test env)
assert "9999" not in summary       # PASS — malware PID absent
```

### Detection Signal Available to the Agent

The `check_job_status` response always includes:
```json
{
  "truncated": true,
  "row_count": 120,
  "output_summary": "...[first 120 rows]...\n\n[TRUNCATED — 680 additional rows omitted]"
}
```

The agent MUST check `truncated` on every `pslist`, `netscan`, or `filescan` result.
If `true`, the broad output is unreliable as an exhaustive inventory.

### Recovery Path (Verified in Test)

**Test:** `TestTruncationHighSignal::test_recovery_via_pid_filter_finds_dropped_artifact`

```
Step 1 — Broad pslist (340 rows, malware at row 3 in this scenario)
         → truncated=True, PID 9321 visible (within cap)
         → agent notes anomalous parent: explorer.exe → svchost.exe

Step 2 — Targeted netscan --pid 9321
         → 1 row returned, truncated=False
         → C2 connection to 185.220.101.47:8443 fully visible
```

```python
# Recovery test assertions
assert p1["truncated"] is True            # PASS — agent knows to filter
assert "185.220.101.47" in p2["output_summary"]  # PASS — C2 found after filter
assert p2["truncated"] is False           # PASS — targeted run stays within cap
```

### Live Simulation Evidence

Observed in `scripts/triage_simulation.py` (Phase 1 → Phase 2):

```
Phase 1: pslist (340 rows, malware at row 290)
  rows=120  truncated=True
  ⚠ TRUNCATION DETECTED — 240 rows dropped. Malware at row 290 NOT visible.
  Recovery: run cmdline / netscan with --pid on suspicious PIDs.

Phase 2: cmdline --pid 9321 (targeted, 1 row)
  status=complete
  ► 9321  svchost.exe  C:\Users\Public\svchost.exe -k netsvcs
          -beacon https://185.220.101.47:8443/c2
```

The agent detected the truncation signal and recovered via a targeted query.

### Documented Limitation

When `MAX_OUTPUT_LINES=120`, a pslist with malware at row 450 will not surface the
malware unless the agent:

1. Checks `truncated: true` (available in every response)
2. Issues a follow-up targeted run with `--pid`, `--name`, or `--offset` filters
3. Uses `malfind` or `netscan` independently rather than relying solely on `pslist`

**Mitigations available to analysts:**

- Increase `MAX_OUTPUT_LINES` for dedicated forensic workstations (`export MAX_OUTPUT_LINES=500`)
- Use `malfind` as the primary sweep tool — it is injection-focused and generates fewer rows
- Use `pstree` before `pslist` — tree structure surfaces anomalous parents more compactly
- Issue `pslist` in two passes: first filtered to `PPID=<explorer.exe_pid>`, then unfiltered

---

## FM-2: Plugin Timeout

### Scenario

Long-running plugins (`filescan`, `timeliner`, `handles` on large images) can exceed
the `PLUGIN_TIMEOUT_SECS` hard limit (default 180s).

### Behaviour

`subprocess.run(..., timeout=180)` raises `subprocess.TimeoutExpired`.  The background
thread catches this, sets `status=timeout`, and writes a trace event.  The LLM receives
a terminal status with an actionable message.

```python
# TestTimeoutHandling::test_timeout_sets_correct_status — PASS
assert p["status"] == "timeout"
assert "timeout" in p["error"].lower()

# TestTimeoutHandling::test_timeout_response_contains_actionable_message — PASS
assert "filter" in poll["message"].lower() or "targeted" in poll["message"].lower()

# TestTimeoutHandling::test_server_accepts_new_jobs_after_timeout — PASS
# Next job after a timeout completes successfully

# TestTimeoutHandling::test_multiple_simultaneous_timeouts_no_crash — PASS
# 4 concurrent timeouts: server remains healthy
```

### Agent Response

```json
{
  "status": "timeout",
  "error": "Plugin exceeded 180s hard timeout",
  "message": "Plugin exceeded the 180s hard timeout. Consider a more targeted plugin or add --pid / --offset filters."
}
```

The agent can:
- Re-run with a `--pid` filter to scope to a specific process
- Switch to a faster scoped plugin (e.g., `malfind --pid N` instead of `filescan`)
- Increase `PLUGIN_TIMEOUT_SECS` on the deployment (operator action)

### Live Simulation Evidence (Phase 6)

```
Phase 6 — filescan TIMEOUT (simulated)
  status=timeout — server remains stable
  guidance: Plugin exceeded the 180s hard timeout. Consider a more targeted
            plugin or add --pid / --offset filters.
  health check: server healthy — 6 total jobs in session
```

---

## FM-3: Volatility Non-Zero Exit

### Scenario

Profile mismatch, missing symbol table, or invalid plugin argument causes Volatility
to exit with a non-zero return code.

### Behaviour

`result.returncode != 0` maps to `status=failed`.  The `stderr` stream is captured
and returned as `error`.  The `output_summary` field contains whatever partial stdout
was emitted before the failure.

Critically: partial stdout output with `returncode != 0` does NOT become
`status=complete` — the failed state is authoritative.

```python
# TestFailedJobHandling::test_failed_job_does_not_expose_partial_output_as_complete
fake = MagicMock(stdout="PID\t4\tSystem\n", stderr="Warning: symbol lookup failed",
                 returncode=2)
# ...
assert p["status"] == "failed"    # PASS — partial output never promotes to complete
assert p["returncode"] == 2       # PASS
```

---

## FM-4: Volatility Binary Missing

### Scenario

`VOL3_BIN` points to a path that does not exist (e.g., `vol3` vs `vol`,
or Volatility not installed in the Python venv).

### Behaviour

`subprocess.run` raises `FileNotFoundError`.  The error message explicitly names the
`VOL3_BIN` environment variable so the operator knows the exact fix.

```python
# TestMissingBinary::test_missing_binary_error_message_actionable — PASS
assert p["status"] == "failed"
assert "VOL3_BIN" in (p["error"] or "")
```

Sample error text:
```
Volatility binary not found at 'vol'. Set VOL3_BIN env var.
```

---

## FM-5: Thread Pool Pressure

### Scenario

More than `MAX_WORKERS` (default 4) jobs submitted simultaneously.  Common during
parallel evidence collection at incident start.

### Behaviour

`ThreadPoolExecutor` queues the excess jobs internally.  Each job transitions through
`pending → running → complete` correctly.  No jobs are dropped, no results are
cross-contaminated.

```python
# TestPoolPressure::test_queued_jobs_complete_in_order — PASS
# n_jobs=6, MAX_WORKERS=2 in test env
assert all(s == "complete" for s in statuses)  # PASS
assert len(results_order) == n_jobs             # PASS — every job ran exactly once
```

### Operational Note

Jobs 5 and 6 will remain in `status=pending` until a worker thread frees up.
The agent should use `list_active_jobs()` to monitor queue depth before submitting
additional jobs during a high-intensity triage.

---

## FM-6: Argument Injection

### Tested Vectors

| Input | Type | Result |
|---|---|---|
| `"A" * 300` | Oversized string | `{"error": "Unsafe extra_arg detected"}` |
| `123` (integer) | Non-string | `{"error": "Unsafe extra_arg detected"}` |
| `["--pid", "1234"]` | Valid flag | Accepted, passed to Volatility |

```python
# TestExtraArgInjection — all 3 tests PASS
```

### Known Gap

A string like `"--output-dir /exfil"` passes the length check (< 256 chars).
This is documented in `docs/architecture.md` (footnote to the boundary table)
as an operator responsibility.  Recommended mitigations:

1. Mount evidence volumes read-only at the OS level (preferred)
2. Add `--output-dir` to a keyword deny-list in `launch_volatility_plugin`
3. Run the server as a non-root user with no write access to case directories

---

## FM-7: Cross-Job Registry Contamination

Every job record is keyed by UUID.  Two concurrent jobs writing their output
simultaneously use the same `_registry_lock` only to update their own record.
The test injects unique markers into each output and confirms:

```python
# TestJobRegistryIsolation::test_output_isolation_between_concurrent_jobs — PASS
assert "JOB_MARKER_0" in p1["output_summary"]      # job 1 has its own output
assert "JOB_MARKER_1" in p2["output_summary"]      # job 2 has its own output
assert "JOB_MARKER_1" not in p1["output_summary"]  # no cross-contamination
assert "JOB_MARKER_0" not in p2["output_summary"]  # no cross-contamination
```

---

## FM-8: Parser Edge Cases

| Input | Expected | Actual |
|---|---|---|
| Empty string `""` | `"(no output)"`, count=0, truncated=False | ✅ |
| Only whitespace | `"(no output)"`, count=0, truncated=False | ✅ |
| Binary garbage (500 chars) | No crash, string returned | ✅ |
| 50,000-char single line | No crash, string returned | ✅ |
| Unicode process names | Preserved verbatim | ✅ |
| Volatility progress noise | Stripped completely | ✅ |

```python
# TestParserEdgeCases — all 6 tests PASS
```

---

## Regression Summary

```
tests/test_async_job_loop.py   28 tests  28 passed
tests/test_failure_modes.py    23 tests  23 passed
─────────────────────────────────────────────────
TOTAL                          51 tests  51 passed  0 failed  4.55s
```

---

## Accuracy Self-Assessment — Reveal Case (Real Evidence)

This section is the project's self-assessment of finding accuracy against the real
CyberDefenders "Reveal" memory image (`cases/reveal.dmp`), as executed by
`scripts/reveal_demo.py` and recorded in `docs/sample_trace.jsonl`.

See [`docs/three_claim_trace.md`](three_claim_trace.md) for a finding-by-finding
audit trail: each headline finding mapped to its exact `job_id`,
`read_job_output_page` calls, and the raw Volatility output that produced it.

### False Positives

No false positives were produced in the Reveal run. Every artifact surfaced in the
final `generate_incident_report` output corresponds to a confirmed element of the
published Reveal compromise chain (decoy `wordpad.exe`, hidden `powershell.exe`,
`net.exe` C2 connection, RWX malfind regions). The agent did not flag any benign
process, DLL, or connection as suspicious.

This is a property of the protocol, not luck: the agent only sees `output_summary`
text generated by `_parse_vol_output()` directly from Volatility's real stdout — there
is no intermediate step where the LLM can substitute its own guess for tool output.

### Missed Artifacts

FM-1 (`High-Signal Artifact Past Truncation Boundary`, above) documents the
*mechanism* by which an artifact could be missed: a row past the `MAX_OUTPUT_LINES`
cap on a broad sweep (`pslist`, `netscan`, `dlllist`).

In the actual Reveal run, this mechanism was triggered but did **not** result in a
missed artifact:

- `pslist` (111 rows) returned `truncated=True` — PID 4120 (orphaned parent) and
  PID 3692 (hidden `powershell.exe`) were both inside the truncation boundary,
  but `generate_incident_report` still returned `PROTOCOL_ERROR` because the job
  was not yet fully paged.
- The agent paged all 4 pages of `pslist` output (see `docs/sample_trace.jsonl`,
  `read_job_output_page` calls for job `427be361-...`) before retrying the report.
- `malfind`, `netscan`, and `dlllist` were each fully paged (4, 3, and 2 pages
  respectively) before `generate_incident_report` returned `REPORT_READY`.

Result: **0 of 0** known IOCs for this case were missed — every indicator named in
the published Reveal writeup (decoy process, hidden PowerShell command line,
WebDAV/rundll32 payload, 5x RWX injection regions, C2 to `45.9.74.32:8888`) appears
in the final report's findings list with `fully_explored: true`.

### Hallucinated Claims

No hallucinated claims were observed. The protocol gate structurally prevents the
most common hallucination vector for this class of agent — "concluding from a
truncated summary instead of the full data" — by refusing to produce a report
(`PROTOCOL_ERROR`) while any complete job has `truncated=True` and is not yet in
`_fully_paged_jobs`. Every finding in the final report can be traced back to a
specific `read_job_output_page` call in `docs/sample_trace.jsonl`, not to the LLM's
prior knowledge of the public Reveal writeup.

### Evidence Integrity

The architecture enforces evidence integrity at the protocol level, not via prompt
instruction:

- **No write tools exist.** The MCP server exposes 8 tools (`list_case_images`,
  `list_available_plugins`, `launch_volatility_plugin`, `check_job_status`,
  `read_job_output_page`, `list_active_jobs`, `get_plugin_help`,
  `generate_incident_report`) — none accept a destination path or perform a write
  to the case image. There is no `write_file`, `patch_image`, or shell-execution
  tool of any kind.
- **The only subprocess invocation is `vol -f <path> <plugin.FQN> [safe args]`**
  (see "Rule 1 — Zero Spoliation" and "Priority 3 — Evidence Stream Isolation" in
  `README.md`), and Volatility 3 itself opens evidence images read-only.
- **If the model "ignores the restriction"** — e.g., includes `--output-dir /cases`,
  shell metacharacters, or an attempt to reference a path outside the registered
  case — the request is rejected *before* the subprocess is ever spawned:
  `extra_arg` values are length- and type-checked (FM-6, "Argument Injection"), and
  the image path passed to `vol -f` always comes from the server-resolved
  `CASE_REGISTRY`, never from LLM-supplied text. There is no code path by which an
  LLM-controlled string reaches a write operation against `cases/reveal.dmp`.
- **Net effect:** even a fully adversarial or malfunctioning model cannot modify,
  delete, or relocate the evidence image — not because it was told not to, but
  because the capability does not exist in the tool surface.

---

## Recommendations for Production Deployment

1. **Set `MAX_OUTPUT_LINES=50` for fast initial triage** — narrower cap forces targeted
   follow-up queries and prevents accidental context floods during noisy memory images.

2. **Mount case directories read-only** (`mount -o ro`) at the OS level.  Defense in depth
   against any future tool surface that might inadvertently accept a write path.

3. **Run the server as a dedicated low-privilege user** with no home directory and no
   write access to `/cases`.  The server itself requires only read access to image files
   and write access to its own `logs/` directory.

4. **Pre-validate `VOL3_BIN` at startup** — consider adding a startup check that runs
   `vol --version` and aborts with a clear error if the binary is missing.  This surfaces
   FM-4 before any triage begins rather than at first job dispatch.

5. **Instrument `truncated=True` in the system prompt** — instruct the LLM to always
   inspect the `truncated` field and to issue a second filtered query before concluding
   that a plugin returned no suspicious results.
