# The Story of VOLBREACH: An Async, Forensic-Safe MCP Protocol Wrapper

## What It Does

VOLBREACH (Protocol-SIFT-Async-Bridge) is a Custom MCP Server that gives any
MCP-compatible LLM client (Claude Desktop, Claude Code, MCP Inspector) safe,
type-safe access to Volatility 3 memory forensics on the SANS SIFT Workstation.

An analyst points the server at a memory image; the LLM agent can then:

- Launch Volatility 3 plugins (`pslist`, `pstree`, `cmdline`, `malfind`, `netscan`,
  `dlllist`, etc.) as non-blocking background jobs and poll for completion -
  eliminating the 4-minute MCP tool-call timeout on scans that take 10-45 minutes.
- Page through large plugin outputs (1,000-50,000+ lines) via disk-backed,
  gzip-compressed pagination with an optional case-insensitive `filter_pattern`,
  keeping the LLM's context window small without losing data.
- Be structurally blocked from prematurely concluding an investigation: the
  `generate_incident_report` tool returns `PROTOCOL_ERROR` if any truncated job
  hasn't been fully paged, forcing exhaustive review before a report is generated.

End-to-end, this lets an LLM agent run a full incident triage against a real memory
image - e.g., the CyberDefenders "Reveal" case - and produce a `REPORT_READY`
incident report (phishing decoy -> hidden PowerShell -> WebDAV/rundll32 payload ->
process injection -> live C2) without ever risking a write to the original evidence
file, because no write or shell-exec tool exists in the server's tool surface.

## Inspiration

In November 2025, Anthropic's security team dropped a threat intelligence report on **GTG-1002** — a state-sponsored threat group utilizing autonomous AI agents to execute reconnaissance, exploit targets, and achieve full domain control at request rates that are physically impossible for human operators. Adversaries now move at machine speed, clocking breakout times ranging from 60 seconds to 8 minutes.

Meanwhile, human incident responders are left manually digging through complex command-line flags on their workstations.

The SANS SIFT Workstation provides an elite arsenal of over 200 forensic tools, but connecting an AI directly to a raw shell creates a catastrophic bottleneck. Standard LLM client-tool connections feature a strict execution timeout barrier of 4 minutes, while a comprehensive Volatility 3 memory scan or an MFT filesystem timeline on a production image routinely takes anywhere from 10 to 45 minutes. When traditional, naive AI wrappers hit this threshold, they drop connections, experience context window degradation, or worse — hallucinate and mutate raw evidence files, violating chain-of-custody.

We were inspired to close this operational gap by building **VOLBREACH**: a forensic-safe execution protocol that enables autonomous AI investigation while enforcing evidence immutability, asynchronous long-running task orchestration, and token-aware result pagination.

## How We Built It

We engineered a custom, type-safe Python Model Context Protocol (MCP) Server running natively on the SANS SIFT Workstation utilizing the FastMCP framework. Instead of exposing generic, hazardous shell execution commands (`execute_shell_cmd`), we built an abstraction layer with highly structured, type-safe Pydantic tool definitions.

The runtime architecture implements six core security and optimization paradigms:

1. **Asynchronous Non-Blocking Workers** — When an agent invokes an intensive memory scan plugin (e.g., `windows.netscan`), the server schedules the command using an optimized worker queue, immediately returning an encrypted tracking token (Job ID) to the client in under 5 milliseconds. The agent polls the task independently via a discrete `check_job_status` tool, completely neutralizing LLM connection timeouts.

2. **Gzip Disk Slicing** — To eliminate the risk of Out-Of-Memory (OOM) crashes under high-volume concurrent loads, all completed plugin outputs are stripped of layout noise and instantly streamed directly to disk as compressed files (`raw_output.txt.gz`) inside an isolated, server-controlled sandbox workspace.

3. **Token-Aware Pagination with Semantic Filtering** — Raw output strings are aggressively truncated at a hard ceiling of 120 lines to protect the LLM from context window rot. To solve the problem of excessive token burn during massive sweeps, we introduced a case-insensitive `filter_pattern` parameter to our `read_job_output_page` tool. The server filters rows natively before slicing pagination boundaries, allowing the agent to execute targeted searches without bloating the prompt context.

4. **The Premature-Conclusion Protocol Gate** — To defeat lazy AI analytical loops, we hardcoded a server-side gate via the `generate_incident_report` tool. If an agent tries to compile a final report while an active job flag shows `truncated: True`, the server blocks execution with a strict `status=PROTOCOL_ERROR`. The agent is structurally forced to exhaustively page or filter through data before forming conclusions.

5. **Process Tree Terminations** — The server prevents orphaned, rogue background workers by utilizing Linux Process Group IDs (`os.setsid`) to group Volatility subprocess child shells. On a timeout event, it fires a group-wide `os.killpg()` signal to ensure zero zombie tasks consume host CPU or IO cycles.

6. **Perimeter Hardening & Resilience** — We implemented a pre-flight disk exhaustion gate using `shutil.disk_usage()` that halts job scheduling if available storage drops below a hard threshold of 5 GB. Furthermore, we encapsulated all tool data streams inside rigid structural XML delimiters (`<untrusted_evidence_stream>`) prepended with an uppercase system notice to completely neutralize indirect prompt injection attempts embedded in memory artifacts.

## Challenges We Faced

The road to a fully verified, 51/51 passing test suite was riddled with major engineering hurdles:

- **The Subprocess Popen Lifecycle Trap** — Shifting from standard synchronous execution to non-blocking background process tracking completely broke our verification suite. When we switched to using Process Group IDs to clean up orphaned workers, we had to refactor 19 distinct subprocess patch sites across our unit tests to gracefully mock the complex two-call `.communicate()` sequence triggered during `TimeoutExpired` exceptions.

- **In-RAM Bloat vs. Disk Race Conditions** — Our initial prototype cached raw strings in an in-memory dictionary. When we moved this to compressed disk files to prevent OOM errors, we introduced potential thread race conditions during simultaneous reads, writes, and worker sweeps. We mitigated this by wrapping all shared state operations inside robust synchronization locks.

- **The Lazy Agent Dilemma** — Early testing revealed that the AI model would read page one of a process list, spot a minor indicator, and immediately halt the investigation to save its context footprint, completely missing deeper hidden threat indicators. Designing the protocol gate to actively reject premature report compilation required careful server-side state tracking but successfully forced the model to think like a senior forensic investigator.

## What We Learned

This development cycle completely reshaped our perspective on AI orchestration in high-stakes defensive environments:

- **Architecture Rules Over Prompts** — You cannot patch critical security flaws or prevent data destruction by telling an LLM "please don't write to the disk" in a system prompt. True safety must be hardcoded at the protocol level.

- **Depth Outperforms Breadth** — Building an incredibly deep, fault-tolerant, and resource-governed wrapper for a single foundational toolkit (like Volatility 3 memory forensics) provides infinitely more defensive value than shallow, fragile coverage over hundreds of unconstrained command utilities.

- **The Power of Standardized Interfaces** — Model Context Protocol (MCP) is a massive force multiplier for the digital forensics and incident response (DFIR) community. By creating predictable standard streams (stdio), we can confidently give autonomous agents access to professional-grade tools without sacrificing evidence integrity or system stability.

## What's Next for VOLBREACH

While our current release is a hardened, production-ready framework verified end-to-end against a real-world, 2.0 GB CyberDefenders memory snapshot (`reveal.dmp`), our engineering roadmap includes:

- **Cryptographic Hash Chaining** — Implementing append-only logs where every frame of the 45-frame JSON-RPC trace is cryptographically bound to the previous event, creating a totally tamper-evident chain of custody.

- **Automated Cross-Source Correlation** — Teaching the agent to map extracted memory injection offsets directly against physical disk Master File Table (MFT) timelines using an integrated plaso/log2timeline server hook.

- **Dynamic Resource Leveling** — Using Linux cgroups to dynamically throttle the CPU allocation of non-essential forensic workers when the SIFT host system faces high computational pressure.
