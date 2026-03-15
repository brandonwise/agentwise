Show HN: Agentwise – a fast MCP security scanner written in Rust

Agentwise scans MCP config files (`.mcp.json`, `claude_desktop_config.json`, `mcp.json`, etc.) for security issues like missing tool allowlists, over-broad filesystem permissions, plaintext secrets, insecure HTTP transport, and known vulnerable packages.

I built it because I’m a Principal Product Manager & Architect at CrowdStrike working in endpoint security/threat intelligence, and I kept seeing MCP setups treated like harmless glue code when they’re really control-plane security boundaries.

I ran a research scan on 61 real public configs (109 server entries total) and every single server had at least one finding (109/109), with missing tool allowlists on 100% of them.

Performance was a priority: the full 65-config aggregate scan completed in 16ms on my run. It’s a single Rust binary with zero runtime dependencies.

Blog post: https://github.com/brandonwise/agentwise/blob/main/blog/i-scanned-50-mcp-servers.md
Repo: https://github.com/brandonwise/agentwise
