# Contributing to agentwise

Thanks for wanting to help make AI agents more secure.

## Quick Start

```bash
git clone https://github.com/brandonwise/agentwise.git
cd agentwise
cargo test        # Run all tests
cargo clippy      # Lint
cargo run -- scan testdata/vulnerable-mcp.json  # Try it
```

## Project Structure

```
src/
├── main.rs           # CLI entry point (clap)
├── config.rs         # MCP config parsing (serde)
├── scanner.rs        # Scan orchestrator
├── score.rs          # Scoring system (0-100)
├── cvedb.rs          # Embedded CVE database
├── rules/
│   ├── mod.rs        # Rule trait + registry
│   ├── auth.rs       # AW-001: Missing authentication
│   ├── filesystem.rs # AW-002: Overpermissioned filesystem
│   ├── shell.rs      # AW-003: Unrestricted shell
│   ├── secrets.rs    # AW-004: Secrets in config
│   ├── transport.rs  # AW-005: Insecure transport
│   ├── cve.rs        # AW-006: Known CVE matching
│   ├── allowlist.rs  # AW-007: Missing allowlist
│   ├── write_tools.rs# AW-008: Write-capable tools
│   ├── network.rs    # AW-009: Unrestricted network
│   └── injection.rs  # AW-010: Prompt injection surface
└── report/
    ├── terminal.rs   # Colorized terminal output
    ├── json.rs       # JSON output
    └── sarif.rs      # SARIF for GitHub Code Scanning
```

## Adding a New Detection Rule

1. Create `src/rules/your_rule.rs`
2. Implement the `Rule` trait:

```rust
pub struct YourRule;

impl Rule for YourRule {
    fn id(&self) -> &'static str { "AW-0XX" }
    fn name(&self) -> &'static str { "your-rule-name" }
    fn check(&self, server_name: &str, server: &McpServer) -> Vec<Finding> {
        let mut findings = vec![];
        // Your detection logic here
        findings
    }
}
```

3. Register it in `src/rules/mod.rs`
4. Add tests
5. Run `cargo test && cargo clippy -- -D warnings`

## Adding CVEs

Edit `cvedb/mcp-cves.json`. Each entry needs:

```json
{
  "id": "CVE-YYYY-XXXXX",
  "package": "@scope/package-name",
  "affected_versions": "<1.2.3",
  "severity": "critical|high|medium|low",
  "description": "What the vulnerability does",
  "fix": "How to fix it"
}
```

## Guidelines

- Run `cargo clippy -- -D warnings` before submitting
- Add tests for new rules (aim for edge cases)
- Keep detection rules focused — one check per rule
- False positives are worse than false negatives

## Code of Conduct

Be kind. Be constructive. We're all here to make AI agents safer.
