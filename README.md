<p align="center">
  <h1 align="center">🛡️ agentwise</h1>
  <p align="center">
    <strong>The fast, offline security scanner for AI agent configurations.</strong>
  </p>
  <p align="center">
    <a href="https://github.com/brandonwise/agentwise/actions"><img src="https://github.com/brandonwise/agentwise/workflows/CI/badge.svg" alt="CI"></a>
    <a href="https://crates.io/crates/agentwise"><img src="https://img.shields.io/crates/v/agentwise.svg" alt="crates.io"></a>
    <a href="#license"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg" alt="License"></a>
    <a href="https://github.com/brandonwise/agentwise/stargazers"><img src="https://img.shields.io/github/stars/brandonwise/agentwise.svg" alt="GitHub Stars"></a>
  </p>
</p>

---

Scans your MCP server configs for security vulnerabilities. One command. Milliseconds. Zero dependencies.

```
$ agentwise scan .

🛡️ agentwise v0.1.0

● Scanned 3 configs (12 servers) in 4ms

  ■ 3 critical  ■ 5 high  ■ 7 medium  ■ 0 low

✖ CRITICAL  .mcp.json → filesystem
  AW-002  Filesystem server with dangerous root access
  Fix: Add "allowedDirectories" to restrict to project directories

✖ CRITICAL  .mcp.json → quickbooks
  AW-001  No authentication on remote MCP server
  Fix: Add authentication via env vars (AUTH_TOKEN, API_KEY, etc.)

▲ HIGH      .mcp.json → filesystem
  AW-006  CVE-2025-53110: Path traversal in server-filesystem <0.6.3
  Fix: Upgrade to >=0.6.3

  Score: 12/100  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  Grade: F
```

## Why agentwise?

30+ CVEs against MCP servers in the last 60 days. 36% of MCP servers have zero authentication. Your AI agent setup is probably vulnerable.

Existing scanners are Python or JavaScript — they need `pip install` or `npm install`, pull dozens of dependencies, and some even require LLM API calls that cost money per scan.

**agentwise is different:**

|  | Python/JS scanners | agentwise |
|--|-------------------|-----------|
| Install | `pip install` / `npm install` | Single binary |
| Speed | Seconds | **Milliseconds** |
| Dependencies | 20-50 packages | **Zero** |
| Offline | Some need LLM APIs | **Fully offline** |
| CI/CD | Install runtime first | Download binary, run |
| Memory safe | No | **Rust** 🦀 |

## Install

### From source (requires Rust)

```bash
cargo install agentwise
```

### Pre-built binary

```bash
curl -sSf https://raw.githubusercontent.com/brandonwise/agentwise/main/install.sh | sh
```

### Homebrew (coming soon)

```bash
brew install brandonwise/tap/agentwise
```

## Usage

```bash
# Scan current directory (auto-detects MCP configs)
agentwise scan .

# Scan a specific config file
agentwise scan ~/.mcp.json

# JSON output (for scripting)
agentwise scan . --format json

# SARIF output (for GitHub Code Scanning)
agentwise scan . --format sarif > results.sarif

# Fail CI on high+ severity findings
agentwise scan . --fail-on high
```

### Supported Configs

agentwise auto-detects and scans:

- `.mcp.json` — Claude Code project-level configs
- `claude_desktop_config.json` — Claude Desktop
- `.cursor/mcp.json` — Cursor editor
- `mcp.json` — Generic MCP configs
- Any JSON file with `mcpServers` passed as argument

## Detection Rules

| ID | Rule | Severity | What It Catches |
|----|------|----------|----------------|
| AW-001 | No authentication | Critical | Remote MCP servers with no auth configured |
| AW-002 | Overpermissioned filesystem | Critical | Filesystem MCP serving `/` or with no `allowedDirectories` |
| AW-003 | Unrestricted shell access | Critical | Shell/exec tools with no restrictions |
| AW-004 | Secrets in config | High | API keys, tokens, passwords in plaintext |
| AW-005 | Insecure transport | High | HTTP (not HTTPS) for remote servers |
| AW-006 | Known CVE match | Critical/High | Package+version matches known MCP vulnerabilities |
| AW-007 | Missing tool allowlist | Medium | All tools available with no filtering |
| AW-008 | Write-capable tools | Medium | Database/file tools that can create/update/delete |
| AW-009 | Unrestricted network | Medium | Fetch/HTTP tools with no domain restrictions |
| AW-010 | Prompt injection surface | Medium | Suspicious patterns in tool descriptions |

## CVE Database

agentwise ships with an embedded database of 22 known MCP vulnerabilities, including:

- **CVE-2025-6514** — Command injection in MCP tool configs (CVSS 10.0)
- **CVE-2026-2256** — Prompt-to-RCE via Shell tool in `ms-agent` (CVSS 10.0)
- **CVE-2025-59536** — RCE via Claude Code project files (CVSS 9.8)
- **CVE-2026-0755** — eval() RCE in `gemini-mcp-tool` (CVSS 9.8)
- **CVE-2026-15503** — Container escape in `mcp-server-docker` (CVSS 9.6)
- **CVE-2026-31024** — SQL injection in `mcp-server-postgres` (CVSS 9.1)
- **CVE-2026-31187** — JS execution in `mcp-server-puppeteer` (CVSS 9.3)
- **CVE-2025-53110/53109** — Path traversal + symlink escape in `server-filesystem`
- **CVE-2025-68143/68144** — Path traversal + argument injection in Git MCP
- **CVE-2026-22091** — SSRF in `mcp-server-fetch`
- **CVE-2026-12847** — Unauthorized access in `mcp-server-slack`
- ...and 10 more across the MCP ecosystem

## Scoring

Every scan produces a security score from 0-100:

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Excellent — minimal risk |
| B | 80-89 | Good — minor issues |
| C | 70-79 | Fair — some concerns |
| D | 50-69 | Poor — significant risks |
| F | 0-49 | Critical — immediate action needed |

## GitHub Action

```yaml
- uses: brandonwise/agentwise-action@v1
  with:
    path: .
    fail-on: high
    format: sarif
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: Security scan
  run: |
    curl -sSf https://raw.githubusercontent.com/brandonwise/agentwise/main/install.sh | sh
    agentwise scan . --fail-on high --format sarif > agentwise.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: agentwise.sarif
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details. The short version:

1. Fork & clone
2. `cargo test` to verify everything passes
3. Add your changes (new rules go in `src/rules/`)
4. `cargo clippy -- -D warnings` for lint
5. Open a PR

## Roadmap

- [x] MCP config scanning (10 rules)
- [x] CVE database (embedded)
- [x] Terminal, JSON, SARIF output
- [x] GitHub Action
- [x] Scoring system (0-100, A-F)
- [ ] Auto-discovery (`agentwise scan --auto`)
- [ ] Custom rule DSL (YAML)
- [ ] Interactive TUI
- [ ] Auto-fix (`agentwise fix`)
- [ ] Hosted API + dashboard

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

---

Built by [@brandonwise](https://github.com/brandonwise). Because your AI agents deserve better security than `"auth": null`.
