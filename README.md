# Protocol-SIFT-Async-Bridge

> **A production-grade, type-safe Custom MCP Server for memory forensics via Volatility 3 — purpose-built to close the 60-second attacker breakout window without triggering LLM timeouts or causing evidence spoliation.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-green.svg)](https://www.python.org/)
[![MCP SDK](https://img.shields.io/badge/MCP-1.9%2B-purple.svg)](https://github.com/modelcontextprotocol/python-sdk)

---

## The Problem This Solves

When a threat actor gains initial access, **the average breakout time to lateral movement is under 60 seconds** in modern intrusion sets. Memory forensics with Volatility 3 is the highest-fidelity detection method — but it has three friction points that make LLM-assisted IR fragile:

| Friction Point | Consequence Without This Server |
|---|---|
| Volatility plugins take 30–180 seconds to run | LLM tool call times out (4-minute limit), loses all output |
| Raw plugin output is 1,000–50,000 lines | Floods the context window; degrades reasoning quality |
| IR analysts want to feed the LLM a memory image path | Path handling in prompts creates evidence spoliation risk |

**Protocol-SIFT-Async-Bridge** eliminates all three with architectural guarantees — not prompt guardrails.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    LLM / MCP Client                          │
│  (Claude, GPT-4o, etc. via Claude Code / custom harness)    │
└────────────────────┬────────────────────────────────────────┘
                     │  JSON-RPC over stdio (MCP protocol)
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Protocol-SIFT-Async-Bridge                      │
│              server/mcp_vol_server.py                        │
│                                                              │
│  ┌──────────────────┐    ┌──────────────────────────────┐   │
│  │   Tool Layer     │    │   Async Execution Engine     │   │
│  │                  │    │                              │   │
│  │ list_case_images │    │  ThreadPoolExecutor          │   │
│  │ list_plugins     │───▶│  (max_workers=4)             │   │
│  │ launch_plugin    │    │                              │   │
│  │ check_job_status │    │  JobRegistry (uuid → record) │   │
│  │ list_active_jobs │    │  threading.Lock protected    │   │
│  │ get_plugin_help  │    └──────────────┬───────────────┘   │
│  └──────────────────┘                   │                   │
│                                         ▼                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │          Security Boundary Layer                      │   │
│  │                                                       │   │
│  │  CASE_REGISTRY: slug → Path (read-only, at startup)  │   │
│  │  ALLOWED_PLUGINS: slug → FQN allow-list              │   │
│  │  _parse_vol_output(): hard cap at MAX_OUTPUT_LINES   │   │
│  └──────────────────────────────────────────────────────┘   │
│                                         │                   │
└─────────────────────────────────────────┼───────────────────┘
                                          ▼
                             ┌────────────────────────┐
                             │   Volatility 3 CLI     │
                             │   (vol -f /cases/...   │
                             │    windows.pslist...)  │
                             └────────────────────────┘
```

---

## The Three Architectural Rules

These are **code-level invariants**, not prompt instructions.  They cannot be bypassed by a malicious prompt, a jailbreak, or a misconfigured system prompt.

### Rule 1 — Zero Spoliation

```python
# server/mcp_vol_server.py, lines ~60–90
CASE_REGISTRY: dict[str, Path] = _load_case_registry()
```

- Memory image paths are **resolved once at server startup** from the `VOL_CASE_IMAGES` environment variable.
- The LLM **never provides a path string**. It provides an opaque `image_slug` key (e.g., `"case-001-win10"`).
- The slug is validated against `CASE_REGISTRY` before any subprocess is spawned.
- Result: a compromised prompt cannot cause Volatility to read `/etc/shadow`, exfiltrate files, or modify evidence.

```
LLM provides:  image_slug="case-001-win10"   ✅
LLM provides:  image_slug="/cases/../etc/passwd"  → rejected, key not in registry  ✅
LLM provides:  image_slug="../../../../bin/bash"  → rejected  ✅
```

### Rule 2 — Async Execution Engine

```python
# server/mcp_vol_server.py
_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# launch_volatility_plugin() — returns in < 5ms
job_id = str(uuid.uuid4())
_executor.submit(_run_volatility, job_id)
return {"job_id": job_id, "status": "pending", ...}

# check_job_status() — returns in < 5ms
record = _get_job(job_id)
return asdict(record)   # status: pending | running | complete | failed | timeout
```

- `launch_volatility_plugin` **never blocks**. It queues work and returns a `job_id` immediately.
- The LLM polls `check_job_status` on its own pacing. A 180-second Volatility run never approaches the 4-minute tool timeout.
- A `PLUGIN_TIMEOUT_SECS` hard limit (default: 180s) terminates runaway plugins and sets `status=timeout`.
- Multiple plugins can run in parallel across different images.

**LLM interaction pattern:**

```
1. launch_volatility_plugin("case-001-win10", "pslist")
   → {"job_id": "abc-123", "status": "pending"}

2. [wait 5s]
   check_job_status("abc-123")
   → {"status": "running", "elapsed_secs": 5.1}

3. [wait 10s]
   check_job_status("abc-123")
   → {"status": "complete", "output_summary": "PID  PPID  ...", "row_count": 120, "truncated": true}
```

### Rule 3 — Context Safety (Output Truncation)

```python
# server/mcp_vol_server.py
MAX_OUTPUT_LINES: int = int(os.environ.get("MAX_OUTPUT_LINES", "120"))

def _parse_vol_output(raw: str) -> tuple[str, int, bool]:
    # 1. Strip Volatility progress spinners / version headers
    # 2. Detect tabular vs. freeform output
    # 3. Keep header rows + first MAX_OUTPUT_LINES data rows
    # 4. Append truncation notice with dropped row count
    ...
```

- A `pslist` on a busy Windows 10 image returns ~800 rows. The LLM sees 120 rows + a notice.
- `malfind` dumps hex blobs that can be megabytes. The LLM sees the first 120 lines.
- The IR analyst can re-run with `--pid` or `--offset` filters to drill into specific entries.
- `MAX_OUTPUT_LINES` is tunable per deployment via environment variable.

---

## Security Boundary Map

This table distinguishes what is enforced by the **server code** vs. what is delegated to **prompt guardrails**. Only the former is reliable in adversarial conditions.

| Control | Enforcement Layer | Can Be Bypassed by Prompt? |
|---|---|---|
| Image path access | Hardcoded registry, resolved at startup | ❌ No |
| Plugin allow-list | `ALLOWED_PLUGINS` dict at startup | ❌ No |
| Extra arg length cap (256 chars) | Input validation in `launch_volatility_plugin` | ❌ No |
| Plugin timeout | `subprocess.run(timeout=...)` | ❌ No |
| Output line cap | `_parse_vol_output()` hard truncation | ❌ No |
| Thread pool size | `ThreadPoolExecutor(max_workers=N)` | ❌ No |
| Write access to evidence | Not exposed — no write tools exist | ❌ No |
| Lateral plugin (e.g. dumpfiles path) | `--output-dir` not in args → analyst sets at deploy time | ✅ Prompt guidance only |
| Investigation strategy | System prompt / LLM reasoning | ✅ Prompt guidance only |
| Report format | System prompt / LLM reasoning | ✅ Prompt guidance only |

---

## Directory Structure

```
Protocol-SIFT-Async-Bridge/
│
├── server/
│   ├── __init__.py
│   └── mcp_vol_server.py       ← Main MCP server (5 tools, async engine)
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py             ← Module reload fixture (clean job registry per test)
│   └── test_async_job_loop.py  ← Full test suite (no real Volatility required)
│
├── logs/
│   └── .gitkeep               ← Session trace logs written here at runtime
│
├── requirements.txt
├── LICENSE
└── README.md
```

---

## MCP Tool Reference

### `list_case_images()`
Returns the read-only registry of available memory images.
```json
{
  "case_images": {
    "case-001-win10": {"slug": "case-001-win10", "path_exists": true, "size_bytes": 4294967296}
  },
  "count": 1
}
```

### `list_available_plugins()`
Returns the curated allow-list of Volatility 3 plugins.
```json
{
  "plugins": [
    {"slug": "pslist", "volatility_fqn": "windows.pslist.PsList"},
    {"slug": "malfind", "volatility_fqn": "windows.malfind.Malfind"}
  ]
}
```

### `launch_volatility_plugin(image_slug, plugin_slug, extra_args?)`
Queues a plugin run. Returns a `job_id` immediately — never blocks.
```json
{
  "job_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "status": "pending",
  "message": "Plugin 'pslist' queued. Poll check_job_status('3fa8...') every 5-15 seconds.",
  "estimated_wait_secs": 30,
  "hard_timeout_secs": 180
}
```

### `check_job_status(job_id)`
Poll for results. Call repeatedly until `status` is `complete`, `failed`, or `timeout`.
```json
{
  "job_id": "3fa85f64-...",
  "status": "complete",
  "plugin_slug": "pslist",
  "image_slug": "case-001-win10",
  "output_summary": "PID\tPPID\tImageFileName\n4\t0\tSystem\n...\n\n[TRUNCATED — 680 rows omitted]",
  "row_count": 120,
  "truncated": true,
  "returncode": 0,
  "queued_at": "2025-06-07T18:00:00Z",
  "started_at": "2025-06-07T18:00:00.1Z",
  "finished_at": "2025-06-07T18:00:45.3Z"
}
```

### `list_active_jobs()`
Situational awareness — lists all jobs in the current session.

### `get_plugin_help(plugin_slug)`
Synchronous `vol <plugin> --help` — returns usage info without loading an image.

---

## Try It Out — Local Execution

### Prerequisites

- Python 3.11+
- Volatility 3 installed: `pip install volatility3` or see [Volatility 3 docs](https://volatility3.readthedocs.io/)
- A memory image file (`.raw`, `.vmem`, `.lime`, etc.)

### Step 1 — Install Dependencies

```bash
git clone https://github.com/yourorg/Protocol-SIFT-Async-Bridge
cd Protocol-SIFT-Async-Bridge
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2 — Configure Case Images

Set the `VOL_CASE_IMAGES` environment variable pointing to your memory images:

```bash
export VOL_CASE_IMAGES='{"case-001-win10": "/path/to/win10.raw", "case-002-linux": "/path/to/linux.lime"}'
```

Or create a `.env` file in the project root:

```env
VOL_CASE_IMAGES={"case-001-win10": "/path/to/win10.raw"}
VOL3_BIN=vol
MAX_OUTPUT_LINES=120
PLUGIN_TIMEOUT_SECS=180
MAX_WORKERS=4
```

> **Without real images:** The server starts and all tools work — `list_case_images()` will report `path_exists: false`, and `launch_volatility_plugin` will fail with a Volatility error. The async job loop and all other tools function normally for testing.

### Step 3 — Register with Claude Code (stdio transport)

Add to your Claude Code MCP configuration (`~/.claude/mcp.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "sift-bridge": {
      "command": "python",
      "args": ["-m", "server.mcp_vol_server"],
      "cwd": "/path/to/Protocol-SIFT-Async-Bridge",
      "env": {
        "VOL_CASE_IMAGES": "{\"case-001-win10\": \"/cases/mem.raw\"}",
        "VOL3_BIN": "vol",
        "MAX_OUTPUT_LINES": "120"
      }
    }
  }
}
```

Restart Claude Code and verify the server is visible with `/mcp`.

### Step 4 — Run the Test Suite (No Volatility or Images Required)

```bash
pytest tests/ -v
```

Expected output:
```
tests/test_async_job_loop.py::TestOutputParser::test_tabular_output_truncated_at_max_lines PASSED
tests/test_async_job_loop.py::TestOutputParser::test_empty_output_handled PASSED
tests/test_async_job_loop.py::TestOutputParser::test_progress_noise_stripped PASSED
tests/test_async_job_loop.py::TestCaseRegistry::test_registry_populated_from_env PASSED
tests/test_async_job_loop.py::TestCaseRegistry::test_user_cannot_inject_path_via_launch PASSED
tests/test_async_job_loop.py::TestPluginAllowList::test_unknown_plugin_rejected PASSED
tests/test_async_job_loop.py::TestAsyncJobLoop::test_job_lifecycle_complete PASSED
tests/test_async_job_loop.py::TestAsyncJobLoop::test_job_fails_on_nonzero_returncode PASSED
tests/test_async_job_loop.py::TestAsyncJobLoop::test_job_timeout_sets_timeout_status PASSED
tests/test_async_job_loop.py::TestAsyncJobLoop::test_parallel_jobs_tracked_independently PASSED
...
```

### Step 5 — Example LLM Session

With Claude Code connected to the server, a forensic investigation session looks like:

```
You: Analyze the memory image for suspicious processes.

Claude: I'll start with a process list. Let me launch pslist first.
[calls launch_volatility_plugin("case-001-win10", "pslist")]
→ job_id: "abc-123"

[waits 10s, calls check_job_status("abc-123")]
→ status: "running", elapsed: 10s

[waits 15s, calls check_job_status("abc-123")]
→ status: "complete", 47 processes, 0 truncated

I can see process ID 4892 "svchost.exe" spawned from an unusual parent (explorer.exe 
rather than services.exe). Let me run malfind to check for injected code.

[calls launch_volatility_plugin("case-001-win10", "malfind", ["--pid", "4892"])]
...
```

---

## Tuning for Your Environment

| Environment Variable | Default | Purpose |
|---|---|---|
| `VOL_CASE_IMAGES` | (demo paths) | JSON map of `slug → absolute path` |
| `VOL3_BIN` | `vol` | Path or name of the Volatility 3 binary |
| `MAX_OUTPUT_LINES` | `120` | Hard cap on rows returned to LLM per job |
| `PLUGIN_TIMEOUT_SECS` | `180` | Hard kill timeout for Volatility subprocess |
| `MAX_WORKERS` | `4` | ThreadPoolExecutor concurrency limit |

---

## Extending the Plugin Allow-List

Edit `ALLOWED_PLUGINS` in `server/mcp_vol_server.py`:

```python
ALLOWED_PLUGINS: dict[str, str] = {
    ...
    # Add new plugins here — slug: fully-qualified Volatility 3 name
    "vadinfo": "windows.vadinfo.VadInfo",
    "modules":  "windows.modules.Modules",
}
```

The slug is what the LLM uses. The FQN is what the server passes to the binary. This separation means the LLM cannot enumerate or execute arbitrary Volatility plugins — only what an analyst has explicitly approved.

---

## License

MIT — see [LICENSE](LICENSE)

---

## Acknowledgements

- [Volatility Foundation](https://volatilityfoundation.org/) — Volatility 3 memory forensics framework
- [Anthropic MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) — Model Context Protocol server primitives
- [SANS SIFT Workstation](https://www.sans.org/tools/sift-workstation/) — Forensic workstation this project is designed to integrate with
