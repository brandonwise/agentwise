# Agentwise — Project Plan (v2, revised)

**"ripgrep for AI agent security."**
A fast, offline Rust CLI that scans MCP server configs for vulnerabilities. Single binary. Zero dependencies. Beautiful output.

---

## Reality Check

This is a **crowded space**. At least 12 tools exist:

| Tool | ⭐ | Language | Weakness |
|------|-----|----------|----------|
| Snyk/agent-scan | 1,865 | Python | Enterprise-heavy, requires pip/uvx |
| splx-ai/agentic-radar | 927 | Python | Workflow-focused, not config scanning |
| Cisco/mcp-scanner | 843 | Python | Enterprise, narrow |
| mcp-shield | 547 | TypeScript | npm dependency chain |
| AgentAudit | 107 | JavaScript | Requires LLM API calls ($$$) |
| agentshield | 106 | TypeScript | npm, limited rules |
| aguara | 53 | Go | New, limited scope |

**Every single one is Python, JavaScript, or TypeScript.**
Zero dominant Rust tools. That's our angle.

---

## Why We Still Win

The analogy isn't "Trivy for AI agents" (taken). It's **ripgrep vs grep.**

| | Python/JS Tools | agentwise |
|--|----------------|-----------|
| Install | `pip install` / `npm install` / `uvx` | `curl \| sh` → single binary |
| Speed | Seconds (Python startup + deps) | Milliseconds |
| Dependencies | pip/npm ecosystem, sometimes LLM API keys | Zero |
| Offline | Some require internet/LLM calls | Fully offline |
| CI/CD | Heavy — install Python/Node runtime | Download binary, run, done |
| Memory safety | N/A | Rust — a security tool in a memory-safe language |

**The pitch:** "Why install Python and 47 dependencies to scan 3 JSON files?"

---

## v0.1 — Ship Narrow, Ship Fast (2 weeks)

### What It Does
Scans MCP server configurations. That's it. Does one thing, does it best.

**Configs detected and scanned:**
- `.mcp.json` (Claude Code project-level)
- `claude_desktop_config.json` (Claude Desktop)
- `.cursor/mcp.json` (Cursor)
- `~/.config/windsurf/mcp.json` (Windsurf)
- Any MCP config passed as argument

### Detection Rules (10, hardcoded in Rust)

| ID | Name | Severity | What It Catches |
|----|------|----------|----------------|
| AW-001 | No authentication | Critical | MCP server with no auth configured |
| AW-002 | Overpermissioned filesystem | Critical | Filesystem MCP with no `allowedDirectories` |
| AW-003 | Unrestricted shell access | Critical | Shell/exec tools with no restrictions |
| AW-004 | Secret in config | High | API keys, tokens, passwords in plaintext |
| AW-005 | Insecure transport | High | HTTP (not HTTPS) for remote MCP servers |
| AW-006 | Known CVE match | Critical | Package+version matches known MCP CVEs |
| AW-007 | Missing tool allowlist | Medium | All tools available, no filtering |
| AW-008 | Write-capable tools | Medium | Tools that can create/update/delete without explicit opt-in |
| AW-009 | Unrestricted network | Medium | Fetch/HTTP tools with no domain restrictions |
| AW-010 | Prompt injection surface | Medium | Tool descriptions with suspicious instruction patterns |

### CVE Database (embedded, ~30 entries)
Hardcoded JSON. Top MCP CVEs with package name + affected versions:
- CVE-2025-53110 (Filesystem MCP path traversal)
- CVE-2025-59536 (Claude Code project file RCE)
- CVE-2026-21852 (Claude Code RCE)
- CVE-2025-6514 (MCP tool config command injection, CVSS 10.0)
- CVE-2025-68143/68144 (Git MCP path traversal + arg injection)
- CVE-2025-54073 (mcp-package-docs command injection)
- CVE-2026-27896 (Go SDK parsing bypass)
- ~20 more from the "30 CVEs in 60 days" research

### Output

**Terminal (default):** Colorized, severity-sorted, with fix suggestions:
```
$ agentwise scan .

🛡️ agentwise v0.1.0 — scanned 4 configs in 2ms

⚠️  3 critical · 5 high · 4 medium

CRITICAL  .mcp.json → filesystem-server
  AW-002  Filesystem MCP has no allowedDirectories restriction
  Fix: Add "allowedDirectories": ["/path/to/project"] to args

CRITICAL  .mcp.json → filesystem-server
  AW-006  CVE-2025-53110: Path traversal in @modelcontextprotocol/server-filesystem <0.6.3
  Fix: Upgrade to >=0.6.3 or >=2025.7.1

HIGH      claude_desktop_config.json → fetch-server
  AW-005  Remote MCP server using HTTP, not HTTPS
  Fix: Change url to https://

Score: 31/100 (Grade: D)
```

**JSON:** `--format json` for CI/CD piping
**SARIF:** `--format sarif` for GitHub Code Scanning integration

### Scoring
0-100 with letter grades. Simple weighted formula:
- Critical finding: -20 points
- High: -10 points
- Medium: -5 points
- Low: -2 points
- Base: 100

### CLI

```bash
agentwise scan .                    # Scan current directory
agentwise scan ~/.mcp.json          # Scan specific file
agentwise scan . --format json      # JSON output
agentwise scan . --format sarif     # SARIF output
agentwise scan . --fail-on high     # Exit code 1 if high+ found (CI gating)
agentwise --version                 # Version
```

That's it for v0.1. No TUI, no custom rules, no auto-fix, no LangChain/CrewAI.

---

## Technical Architecture

### Language: Rust 🦀

### Crate Structure (simplified for v0.1)

```
agentwise/
├── src/
│   ├── main.rs              # CLI entry (clap)
│   ├── scanner.rs            # Core scan orchestrator
│   ├── config.rs             # MCP config parser (serde)
│   ├── rules/
│   │   ├── mod.rs            # Rule trait + registry
│   │   ├── auth.rs           # AW-001: No authentication
│   │   ├── filesystem.rs     # AW-002: Overpermissioned filesystem
│   │   ├── shell.rs          # AW-003: Unrestricted shell
│   │   ├── secrets.rs        # AW-004: Secrets in config
│   │   ├── transport.rs      # AW-005: Insecure transport
│   │   ├── cve.rs            # AW-006: Known CVE matching
│   │   ├── allowlist.rs      # AW-007: Missing tool allowlist
│   │   ├── write_tools.rs    # AW-008: Write-capable tools
│   │   ├── network.rs        # AW-009: Unrestricted network
│   │   └── injection.rs      # AW-010: Prompt injection surface
│   ├── report/
│   │   ├── mod.rs
│   │   ├── terminal.rs       # Colorized terminal output
│   │   ├── json.rs           # JSON reporter
│   │   └── sarif.rs          # SARIF reporter
│   ├── cvedb.rs              # Embedded CVE database
│   └── score.rs              # Scoring system
├── cvedb/
│   └── mcp-cves.json         # CVE data (embedded at compile time)
├── testdata/                  # Vulnerable config fixtures
├── tests/                     # Integration tests
├── .github/
│   └── workflows/
│       └── ci.yml            # Build + test + clippy + cross-compile
├── action.yml                 # GitHub Action
├── Cargo.toml
├── Cargo.lock
├── LICENSE-MIT
├── LICENSE-APACHE
├── install.sh                 # curl | sh installer
└── README.md
```

**No workspace. No 5 crates.** Single crate, simple structure. Split later if needed. Ship now.

### Key Dependencies
- `clap` — CLI argument parsing
- `serde` + `serde_json` — Config parsing
- `colored` / `owo-colors` — Terminal colors
- `glob` / `walkdir` — File discovery
- `regex` — Pattern matching for secrets/injection
- `include_str!` — Embed CVE database at compile time

### GitHub Action

```yaml
- uses: brandonwise/agentwise-action@v1
  with:
    fail-on: high
```

Downloads pre-built binary, runs scan, uploads SARIF. No runtime dependencies.

---

## Launch Strategy

### The Research Play (This Is What Gets Stars)

**Before launching the tool, publish the research.**

"A CrowdStrike PM Scanned 50 MCP Servers — Here's What I Found"

1. Collect the top 50 MCP servers by stars/popularity
2. Run agentwise against all of them
3. Compile findings into a compelling blog post with data tables
4. Include scary highlights (CVEs found, auth gaps, etc.)
5. Link to the tool at the bottom

The research IS the marketing. The tool is the proof.

### The Benchmark Play

Run the same scan with:
- agentwise (Rust)
- Snyk/agent-scan (Python)
- Cisco/mcp-scanner (Python)
- mcp-shield (TypeScript)

Publish speed comparison. If agentwise scans 50 configs in 50ms while Python tools take 5 seconds, that's a headline.

### Launch Channels (Tuesday/Wednesday, 9-10 AM Pacific)

| Channel | Angle |
|---------|-------|
| Hacker News | "Show HN: I scanned 50 MCP servers for security issues — here's what I found (Rust CLI)" |
| r/rust | "My first real Rust project: a security scanner for AI agents. 100x faster than the Python alternatives" |
| r/netsec | Technical deep-dive on MCP CVEs with scan results |
| r/cybersecurity | "36% of MCP servers have zero auth — here's how to check yours" |
| X/Twitter | Thread with terminal GIF + key findings + benchmark |
| Dev.to | Cross-post of blog |

### Pre-Launch Checklist
- [ ] README with: hero banner, terminal GIF (VHS), one-command install, badge wall
- [ ] Blog post written and ready
- [ ] Benchmark data collected
- [ ] 50-server scan results compiled
- [ ] X thread drafted (7-8 tweets)
- [ ] 3-5 early stars from friends/colleagues

---

## Timeline (Revised — Tighter)

### Week 1: Working Scanner
- [ ] Cargo project scaffold
- [ ] MCP config parser (serde)
- [ ] 10 detection rules
- [ ] Terminal reporter (gorgeous from day 1)
- [ ] JSON reporter
- [ ] Scoring system
- [ ] 50+ tests
- [ ] CI (build + test + clippy + cross-compile for Linux/macOS/Windows)

### Week 2: Launch Prep
- [ ] SARIF reporter
- [ ] GitHub Action
- [ ] `--fail-on` flag
- [ ] `install.sh` script
- [ ] Pre-built release binaries (GitHub Releases)
- [ ] Homebrew tap
- [ ] Run the 50-server scan
- [ ] Write the blog post
- [ ] Polish README (terminal GIF, badges, install instructions)
- [ ] Run benchmarks vs Python tools
- [ ] Draft X thread

### Week 3: Launch
- [ ] Publish blog post
- [ ] Launch on all channels (same day)
- [ ] Engage every comment within 24h
- [ ] Submit to awesome-rust, awesome-security lists

### Week 4+: Iterate Based on Feedback
- [ ] Whatever users actually ask for
- [ ] New CVEs → new detection rules (weekly releases)
- [ ] Auto-discovery of configs (find all MCP configs on system)

---

## What Comes Later (v0.2+, only if v0.1 gets traction)

| Version | Feature | Why |
|---------|---------|-----|
| v0.2 | Auto-discovery (`agentwise scan --auto`) | Find all MCP configs system-wide |
| v0.3 | Custom rule DSL (YAML) | Let community write rules |
| v0.4 | Attack chain analysis | Multi-tool vulnerability chains |
| v0.5 | Interactive TUI | The lazygit moment |
| v0.6 | Auto-fix (`agentwise fix`) | From detection to remediation |
| v1.0 | Hosted API + paid tier | Revenue |

**Do not build these until v0.1 proves people care.**

---

## Revenue Path (If Stars Come)

### Free forever
- CLI tool
- All detection rules
- All output formats
- GitHub Action

### Pro ($9/mo) — only if demand exists
- Hosted API for CI/CD (no binary download needed)
- Real-time CVE alerts
- Team dashboard
- Private scan history

### Math
- Need ~30 paying users to cover subscription costs (~$270/mo)
- At 1-3% conversion from stars, need 1,000-3,000 stars
- v0.1 goal is 100 stars — revenue is NOT the v0.1 goal

---

## Risks (Honest)

| Risk | Real Talk |
|------|-----------|
| Snyk adds Rust support | They won't. Their ecosystem is Python. But they have brand power. |
| Space gets even more crowded | It will. Speed matters — ship in 2 weeks, not 5. |
| Rust learning curve slows you down | AI agents (Claude Code) can write the Rust. You review + iterate. |
| 100 stars doesn't happen | Then the research post still has value for your personal brand. Not wasted effort. |
| Nobody cares about speed | For CI/CD pipelines, speed actually matters. Python cold start is real pain. |

---

## Success Criteria

**Minimum viable success (100 stars):**
- Tool works, scans MCP configs, produces useful output
- Blog post gets read
- A few people actually use it in their CI

**Good outcome (500 stars):**
- Community contributions start coming
- Listed in awesome-* repos
- Start building v0.2 features

**Great outcome (1,000+ stars):**
- Becomes a go-to recommendation
- Start exploring revenue
- Conference talk material

---

## Next Step: Build

The repo exists at `~/clawd/projects/agentwise`. Structure is scaffolded.

Priority order:
1. `Cargo.toml` with dependencies
2. MCP config parser (`config.rs`)
3. First 3 rules (auth, filesystem, secrets)
4. Terminal reporter (make it pretty)
5. Get `agentwise scan testdata/` working end-to-end
6. Add remaining 7 rules
7. JSON + SARIF output
8. CI + cross-compilation
9. README
10. Research scan + blog post

---

*Revised: 2026-03-14*
*Status: Ready to build*
*Owner: Brandon Wise (@brandonwise)*
