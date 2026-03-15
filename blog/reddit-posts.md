# Reddit Post Drafts

## r/rust

I built a Rust CLI called **agentwise** to scan MCP configs for security issues.

I wanted a scanner that is fast, local-first, and dependency-light. Most tools in this space are Python/TS and require runtime setup before you can even test a config. Agentwise is a single binary and scans in milliseconds.

On my research run, it scanned **65 config files / 109 MCP server entries in 16ms**. The rules cover missing `allowedTools`, unrestricted filesystem access (`allowedDirectories` missing), plaintext secrets, insecure HTTP endpoints, CVE matching, and supply-chain signals.

I tested it against real public configs collected from GitHub/tutorials/official docs. Every server scanned had at least one issue (109/109), which was sobering.

If anyone here wants to look at architecture/perf tradeoffs (parsing, rule engine, output formatting, CI SARIF path), I’d love feedback from Rust folks.

Repo: https://github.com/brandonwise/agentwise

---

## r/netsec

I ran a scan of public MCP configs and the result was rough: **109/109 server entries had at least one security issue**.

Dataset: 61 external public configs (plus combined derived sets), 65 files total, 109 server entries.

Top findings:
- Missing tool allowlist (`AW-007`): **109 findings**
- Filesystem without `allowedDirectories` (`AW-002`): **9 findings (8.26%)**
- Unrestricted network access (`AW-009`): **6 findings**
- Insecure HTTP transport (`AW-005`): **2 findings**
- Hardcoded secret pattern (`AW-004`): **2 findings**, including a real OpenRouter/OpenAI-style key pattern in a public config

The main takeaway for me: MCP risk right now is less about exotic zero-days and more about basic control failures in config hygiene. In agent systems, “medium” findings stack into practical attack paths fast.

Tool I used/built for this: https://github.com/brandonwise/agentwise

---

## r/cybersecurity

If your org is adopting AI agents with MCP, treat your MCP configs like privileged security artifacts, not convenience files.

I scanned a corpus of real public MCP configurations and found issues in every server entry scanned (109/109). The most common problem was missing tool allowlists on **100%** of servers. I also saw unrestricted filesystem setups, insecure HTTP endpoints, and plaintext key patterns in public repos.

Why this matters: MCP can expose filesystem operations, API access, browser actions, and other high-impact capabilities. If those aren’t constrained, one prompt-injection path can turn into broad environment access.

Basic hardening that should be standard:
- Add explicit `allowedTools` for every server
- Add narrow `allowedDirectories` for filesystem servers
- Enforce HTTPS-only remote endpoints
- Remove hardcoded secrets from config files
- Add config scanning to CI (`--fail-on high`)

I wrote up the full methodology + data sources and published the scanner here:
https://github.com/brandonwise/agentwise
