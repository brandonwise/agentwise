# Agentwise Launch Workstreams

## Pipeline Architecture
Each workstream runs as an autonomous sub-agent. Dependencies are enforced via gates.

```
┌─────────────────┐    ┌─────────────────┐
│  WS-1: Release  │    │  WS-2: Research │
│  Engineering    │    │  50-Server Scan │
└────────┬────────┘    └────────┬────────┘
         │                      │
         │              ┌───────▼────────┐
         │              │  WS-3: Content │
         │              │  Blog + Assets │
         │              └───────┬────────┘
         │                      │
         ├──────────────────────┤
         │                      │
┌────────▼──────────────────────▼────────┐
│          WS-4: QA & Security           │
│  Test installs, audit, final review    │
└────────────────────────────────────────┘
```

## Status

### WS-1: Release Engineering 🔧
- [ ] Cross-compile CI workflow (Linux amd64/arm64, macOS amd64/arm64, Windows amd64)
- [ ] GitHub Release with binaries + checksums
- [ ] Homebrew tap (brandonwise/homebrew-tap)
- [ ] install.sh auto-detect script
- [ ] crates.io publish prep (verify metadata)
**Status:** NOT STARTED
**Agent:** TBD

### WS-2: Research Scan 🔍
- [ ] Collect 50 real MCP server configs from GitHub/npm/docs
- [ ] Run agentwise scan on all 50
- [ ] Compile statistics (% with auth issues, CVEs, etc.)
- [ ] Generate JSON report for blog post data
**Status:** NOT STARTED
**Agent:** TBD
**Gate:** Data must be real scans, not fabricated

### WS-3: Content & Launch Assets ✍️
- [ ] Blog post: "I Scanned 50 MCP Servers — Here's What I Found"
- [ ] X/Twitter thread (7-8 posts with terminal screenshots)
- [ ] HN Show post draft
- [ ] r/rust post draft
- [ ] r/netsec + r/cybersecurity post draft
**Status:** BLOCKED on WS-2
**Gate:** Blog uses real data from WS-2 scan results only

### WS-4: QA & Security Gate 🛡️
- [ ] Test cargo install from crates.io
- [ ] Test binary download + install.sh
- [ ] Test Homebrew install
- [ ] Run agentwise on itself (meta-scan)
- [ ] Audit dependencies (cargo audit)
- [ ] Test all output formats (terminal, json, sarif)
- [ ] Test --fail-on with CI workflow
- [ ] Final README review
**Status:** BLOCKED on WS-1
**Gate:** All install methods work, all tests pass, zero audit findings

## Launch Day Sequence
1. Publish crates.io
2. Create GitHub Release with binaries
3. Publish Homebrew tap
4. Post blog
5. Submit to HN (Tue/Wed 9-10 AM Pacific)
6. Post X thread
7. Post r/rust, r/netsec, r/cybersecurity
8. Monitor + respond to all comments within 24h
