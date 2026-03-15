# I Scanned 109 MCP Servers and Found Security Issues in Every Single One

Every MCP server I scanned had at least one security issue. Here's what I found.

I’m Brandon Wise, a Principal Product Manager & Architect at CrowdStrike focused on endpoint security and threat intelligence. I built **agentwise** as a side project to answer a simple question: **how bad are real MCP configurations in the wild?**

I expected to find problems. I didn’t expect a 100% hit rate.

## Why this matters

MCP is quickly becoming a standard way to give AI agents powerful capabilities: shell execution, filesystem access, Git operations, browser automation, internal API calls, and more.

That also means MCP is a fresh attack surface.

The ecosystem already has roughly **30 CVEs in ~60 days** worth discussing, and configuration risk is often the shortest path to compromise. MCP also frequently sits in front of agents with shell and filesystem capabilities, and poor or missing auth controls still show up across the broader ecosystem.

In practice, many agent setups are one misconfigured JSON file away from:

- excessive local file access,
- unrestricted outbound network actions,
- exposed credentials in plaintext,
- broad tool exposure with no effective guardrails.

When an agent has tool access and your config is weak, prompt injection and lateral movement stop being theoretical.

## Methodology

This was not synthetic data.

I collected real MCP config examples from public sources and scanned them directly.

### Dataset

- **61 external source-derived configs** (single-server normalized files)
- **4 combined test configs** generated from those same real entries (no fabricated server definitions)
- **65 total config files** scanned
- **109 total server entries** scanned

All source configs were pulled from public GitHub repos or docs and are linked in `research/FINDINGS.md`.

### Scanner + commands

I used `agentwise` (the Rust scanner I’m building) and ran:

```bash
cargo run -- scan research/configs/ --live --format json > research/scan-results.json
cargo run -- scan research/configs/ --live > research/scan-results-terminal.txt
```

Aggregate terminal result:

```text
● Scanned 65 configs (109 servers) in 16ms
■ 0 critical  ■ 13 high  ■ 117 medium  ■ 0 low
Score: 0/100  Grade: F
```

A note on scoring so nobody gets tripped up: the **aggregate score** is one combined score across all findings in one run, so it bottoms out fast. I also scanned each config individually:

- **Average per-config score:** 89.00/100
- **Best config:** 95/100 (A)
- **Worst config:** 5/100 (F)

## Key findings

### 1) 100% missing tool allowlists

- Rule: **AW-007**
- Count: **109 / 109** server entries
- Impact: every server exposed tools without an explicit allowlist boundary.

This was the biggest and most consistent gap by far.

From scan output:

```text
● MEDIUM ... → fetch AW-007
  No tool allowlist configured
  Fix: Add "allowedTools" to restrict which tools are available
```

If you don’t constrain tool availability, your blast radius becomes “whatever the server provides.”

### 2) 8.26% had unrestricted filesystem access

- Rule: **AW-002**
- Count: **9 / 109**
- Impact: filesystem servers with no `allowedDirectories` restriction.

From scan output:

```text
▲ HIGH ... → filesystem AW-002
  Filesystem server without allowedDirectories
  Fix: Add "allowedDirectories" to restrict filesystem access scope
```

This is a direct containment failure. Filesystem MCP should be scoped narrowly to specific project paths, not left broad.

### 3) Real credentials in public configs

- Rule: **AW-004**
- Count: **2 / 109 (1.83%)**
- Notable: OpenRouter/OpenAI-style key pattern detected in public config (`browserbase-local`).

From scan output:

```text
▲ HIGH ... → browserbase-local AW-004
  OpenAI API key in env var
  Fix: Use environment variable references instead of hardcoded secrets
```

This is exactly the kind of issue that turns “just a sample config” into credential leakage.

### 4) HTTP endpoints are still present

- Rule: **AW-005**
- Count: **2 / 109 (1.83%)**
- Notable server: `service-desk-plus`

From scan output:

```text
▲ HIGH ... → service-desk-plus AW-005
  Insecure HTTP URL in args
  Fix: Change URL to use https://
```

If transport isn’t encrypted, you’re increasing exposure for tokens, sessions, and server interactions.

### 5) Network-capable servers are often unconstrained

- Rule: **AW-009**
- Count: **6 / 109**
- Impact: fetch/browser-style tools with effectively unrestricted domain access.

This matters because MCP servers are often used by agents that ingest untrusted text. Prompt injection + unconstrained network access is a bad combo.

## What this means in practice

The raw counts are useful, but the **combinations** matter more than any single finding.

A typical risky pattern in this dataset looked like this:

1. No `allowedTools` boundary (**AW-007**)  
2. One high-risk capability exposed (filesystem or remote transport)  
3. No secondary constraints (directory allowlist, domain restrictions, TLS-only)

That creates multi-step failure paths where a single malicious prompt can push an agent into behavior the operator never intended.

### Rule distribution (from this scan)

- **AW-007 (missing tool allowlist): 109 findings**
- **AW-002 (filesystem without `allowedDirectories`): 9 findings**
- **AW-009 (unrestricted network access): 6 findings**
- **AW-005 (insecure HTTP transport): 2 findings**
- **AW-004 (hardcoded secrets): 2 findings**

A few observations:

- The ecosystem is not mostly “critical CVE exploits” right now in this sample.  
  It’s mostly **configuration debt**.
- Config debt is still dangerous because it compounds.  
  Medium findings stacked together create practical attack paths.
- The hardest problems to catch manually are the boring ones: scope creep, tool sprawl, copied examples, and stale secrets.

### Important nuance

In this dataset, some headline risks came back lower than expected:

- **No-auth remote endpoints (AW-001): 0/109**
- **Shell/exec exposure (AW-003): 0/109**
- **Known CVE matches (AW-006): 0/109**

That does **not** mean MCP is safe by default. It means this specific corpus skewed toward configs that had other classes of problems.

The data still says every scanned server had at least one issue, and the dominant issue (missing allowlists) was universal.

### Why this still deserves urgency

When people hear “medium severity,” they often deprioritize.

That’s a mistake for agent systems.

In a traditional app, one medium finding may be isolated. In an agent workflow, a medium finding can become a control-plane weakness because tools are the execution layer. If your tool boundary is wide open, every downstream control has less value.

## The scariest configs I found

These are not hypothetical examples; they came from public sources in this scan set.

## 1) Public config with a real key pattern (`browserbase-local`)

Source file:

`research/configs/sources/github-config-045-jony2176-fotolibros-argentina-browserbase-local.mcp.json`

Snippet (redacted):

```json
{
  "mcpServers": {
    "browserbase-local": {
      "command": "node",
      "args": [
        "C:\\...\\mcp-server-browserbase\\cli.js",
        "--local"
      ],
      "env": {
        "OPENROUTER_API_KEY": "sk-or-v1-0157...<redacted>...892b0b",
        "CHROME_PATH": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
      }
    }
  }
}
```

`agentwise` output for this single file:

```text
● Scanned 1 config (1 server) in 24ms
■ 0 critical  ■ 1 high  ■ 2 medium  ■ 0 low

▲ HIGH   ...browserbase-local... AW-004
  OpenAI API key in env var
● MEDIUM ...browserbase-local... AW-007
  No tool allowlist configured
● MEDIUM ...browserbase-local... AW-009
  Unrestricted network access

Score: 80/100  Grade: B
```

Why this is bad: this combines **credential exposure + no allowlist + unrestricted network behavior**.

## 2) HTTP SSE endpoint with credentials in config (`service-desk-plus`)

Source file:

`research/configs/sources/github-config-002-pttg-it-sdp-mcp-service-desk-plus.mcp.json`

Snippet:

```json
{
  "mcpServers": {
    "service-desk-plus": {
      "command": "npx",
      "args": ["mcp-remote", "http://studio:3456/sse"],
      "env": {
        "SDP_CLIENT_ID": "...",
        "SDP_CLIENT_SECRET": "..."
      }
    }
  }
}
```

`agentwise` output:

```text
● Scanned 1 config (1 server) in 23ms
■ 0 critical  ■ 1 high  ■ 1 medium  ■ 0 low

▲ HIGH   ...service-desk-plus... AW-005
  Insecure HTTP URL in args
● MEDIUM ...service-desk-plus... AW-007
  No tool allowlist configured

Score: 85/100  Grade: B
```

Why this is bad: if you’re carrying credentials and still using plain HTTP for MCP transport, you’re creating avoidable risk.

## 3) Filesystem server with no directory restrictions (`filesystem`)

Source file:

`research/configs/sources/github-config-040-angelargd8-proyecto1-redes-filesystem.mcp.json`

Snippet:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "C:\\Users\\angel\\Projects",
        "C:\\Users\\angel\\Desktop",
        "C:\\Users\\angel\\OneDrive\\Documentos\\.universidad\\.2025\\s2\\redes\\proyecto1-redes"
      ]
    }
  }
}
```

`agentwise` output:

```text
● Scanned 1 config (1 server) in 23ms
■ 0 critical  ■ 1 high  ■ 1 medium  ■ 0 low

▲ HIGH   ...filesystem... AW-002
  Filesystem server without allowedDirectories
● MEDIUM ...filesystem... AW-007
  No tool allowlist configured

Score: 85/100  Grade: B
```

Why this is bad: the filesystem server has path arguments but no explicit `allowedDirectories` policy boundary.

## What good looks like (before/after)

Most insecure configs in this dataset fail in similar ways: broad tool surface, broad filesystem scope, plaintext credentials, and non-TLS transport.

### Insecure pattern

```json
{
  "mcpServers": {
    "service-desk-plus": {
      "command": "npx",
      "args": ["mcp-remote", "http://studio:3456/sse"],
      "env": {
        "SDP_CLIENT_SECRET": "hardcoded-secret-value"
      }
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\me"]
    }
  }
}
```

### Hardened pattern

```json
{
  "mcpServers": {
    "service-desk-plus": {
      "command": "npx",
      "args": ["mcp-remote", "https://studio.example.com/sse"],
      "env": {
        "SDP_CLIENT_SECRET": "${SDP_CLIENT_SECRET}"
      },
      "allowedTools": ["ticket.read", "ticket.search"]
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"],
      "allowedDirectories": [
        "C:\\Users\\me\\Projects\\agentwise"
      ],
      "allowedTools": ["fs.read_file", "fs.list_dir"]
    }
  }
}
```

Key deltas:

- Use `https://` for remote endpoints.
- Never hardcode keys/tokens; use environment variable references.
- Add `allowedTools` to every server.
- Add narrow `allowedDirectories` for filesystem servers.

## How to check your own configs

You can scan your current project in seconds.

```bash
cargo install agentwise && agentwise scan .
```

Useful follow-ups:

```bash
agentwise scan . --live          # OSV + EPSS enrichment
agentwise scan . --supply-chain  # package + dependency risk signals
agentwise scan . --fail-on high  # CI gate
```

## What’s next for this research

I’m continuing this in four directions:

1. **EPSS-driven prioritization**: rank findings by likely exploitation, not just severity labels.
2. **Supply chain analysis**: expand package trust and dependency risk signals.
3. **CI/CD integration by default**: make MCP scanning a normal build gate.
4. **Larger real-world corpus**: keep pulling public configs and publish trend deltas over time.

This first pass already shows a clear pattern: configuration hygiene is lagging behind agent capability growth.

MCP is useful, but right now a lot of teams are wiring powerful tools into agents without least-privilege boundaries.

If you’re running MCP in dev or production, scan your configs now.

Repo: https://github.com/brandonwise/agentwise
