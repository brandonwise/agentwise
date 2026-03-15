# WS5: System-Wide MCP Config Discovery - Complete

## What Changed

### New: `src/discover.rs`
- `DiscoveredConfig` struct (Serialize/Deserialize) with path, source, exists, server_count, servers fields
- `discover_configs()` — scans all known MCP config locations across Claude Desktop, Claude Code, Cursor, VS Code Continue, Windsurf, Zed, and generic paths
- Platform-aware path generation via `cfg!(target_os)` for macOS, Linux, and Windows
- Walks up from cwd for project-level configs (Claude Code, Cursor, generic)
- Zed support with `mcpServers` and `context_servers` key parsing
- Deduplication by canonical path
- `discover_existing()` and `discover_existing_paths()` helpers
- 14 unit tests covering serialization, path walking, probing, dedup, JSON validity

### Modified: `src/main.rs`
- Added `discover` module declaration
- New `Discover` subcommand with `--json` and `--scan` flags (plus `--format` for scan mode)
- New `--auto` flag on `Scan` subcommand — auto-discovers and scans all system configs
- `--auto` works with all existing flags: `--live`, `--supply-chain`, `--offline`, `--fail-on`, `--format`

### Modified: `src/scanner.rs`
- `scan_paths(&[String])` — scans explicit file paths, combining findings/stats
- `scan_paths_with_live(&[String])` — same with OSV + EPSS enrichment
- `scan_paths_with_supply_chain(&[String], bool)` — same with supply chain + deps.dev
- 3 new tests for scan_paths (multiple files, empty, nonexistent)

### Modified: `src/report/terminal.rs`
- `render_discover(&[DiscoveredConfig])` — pretty terminal output with box drawing, color coding, server tree
- 2 new tests for discover rendering

## Quality Gates

- `cargo build` — clean
- `cargo test` — 149 unit + 24 integration tests pass (0 failures)
- `cargo clippy -- -D warnings` — clean (0 warnings)

## CLI Usage

```
agentwise discover              # Pretty terminal discovery report
agentwise discover --json       # JSON discovery output
agentwise discover --scan       # Discover + scan all found configs
agentwise scan --auto           # Auto-discover and scan
agentwise scan --auto --live    # Auto-discover, scan with live CVE lookups
```
