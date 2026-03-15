# agentwise Benchmark Notes

Reproducible benchmark commands used for README performance claims.

## Environment
- OS: macOS arm64
- Binary: `target/release/agentwise`
- Fixture: `testdata/vulnerable-mcp.json`

## Commands

### agentwise (single fixture)

```bash
hyperfine --warmup 5 --runs 50 -N \
  'target/release/agentwise scan testdata/vulnerable-mcp.json'
```

Observed mean: ~3.1–3.2 ms

### agentwise (research corpus)

```bash
hyperfine --warmup 5 --runs 20 -N \
  'target/release/agentwise scan research/configs/'
```

Observed mean: ~3.9 ms (109 servers)

### Cisco mcp-scanner (comparison)

```bash
mcp-scanner --config-path testdata/vulnerable-mcp.json --analyzers yara
```

Observed wall-clock sample: ~2.68 s

### mcp-shield (comparison)

```bash
mcp-shield --path testdata/vulnerable-mcp.json
```

Observed wall-clock sample: ~60.62 s

## Caveats
- Competitor tools may perform active connections to configured servers by default; this increases runtime and can vary by network state.
- Comparison is meant as practical, default-command UX latency, not a formal academic benchmark.
