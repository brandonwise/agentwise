# X Thread Draft

1/8 (131 chars)
I scanned 109 MCP server entries from real public configs. Every single one had at least one security issue. 109/109. Not a typo. 🔥

2/8 (172 chars)
If you’re new to MCP: it’s the protocol that lets AI apps connect to tools (filesystem, browser, APIs, shell). Great for productivity, also a brand-new security boundary. 🤖

3/8 (169 chars)
Most shocking result: 100% were missing tool allowlists. Every server exposed tools without an explicit allowedTools boundary. That’s the opposite of least privilege. ⚠️

4/8 (193 chars)
I also found a real OpenRouter/OpenAI-style key pattern in a public config. Plaintext secret in repo, right next to runtime settings. This is exactly how credentials leak into attacker hands. 🔑

5/8 (174 chars)
Built a scanner for this: agentwise (Rust). It checks MCP configs for missing allowlists, over-broad filesystem scope, insecure HTTP endpoints, hardcoded secrets, and more. 🦀

6/8 (186 chars)
Speed check: full dataset scan (65 configs, 109 servers) finished in 16ms on my run. Most Python/JS MCP scanners run in seconds, not milliseconds. Rust + single binary is a nice combo. ⚡

7/8 (117 chars)
Try it on your own setup:
cargo install agentwise && agentwise scan .

Repo: https://github.com/brandonwise/agentwise

8/8 (164 chars)
If you run MCP servers in dev or prod, scan now. If agentwise is useful, star the repo so I know to keep shipping features (EPSS, supply-chain checks, CI gating). 🙏
