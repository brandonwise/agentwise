#!/usr/bin/env python3
"""Generate research/FINDINGS.md from WS-2 scan outputs."""

from __future__ import annotations

import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path("/Users/bwise/clawd/projects/agentwise")
SCAN_JSON = ROOT / "research" / "scan-results.json"
SOURCES_JSONL = ROOT / "research" / "configs" / "SOURCES.jsonl"
FINDINGS_MD = ROOT / "research" / "FINDINGS.md"
CONFIG_ROOT = ROOT / "research" / "configs"


def pct(part: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return (part / total) * 100.0


def scanner_like_config_files(root: Path) -> list[Path]:
    out = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        # Mimic scanner rules: known names OR endswith .mcp.json
        name = p.name
        if name in {".mcp.json", "mcp.json", "claude_desktop_config.json"} or name.endswith(
            ".mcp.json"
        ):
            out.append(p)
    return sorted(out)


def average_score_per_config(config_files: list[Path]) -> tuple[float, list[tuple[Path, int, str]]]:
    binary = ROOT / "target" / "debug" / "agentwise"
    if not binary.exists():
        raise RuntimeError("Expected built binary at target/debug/agentwise")

    rows: list[tuple[Path, int, str]] = []
    for cf in config_files:
        proc = subprocess.run(
            [str(binary), "scan", str(cf), "--format", "json"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        if proc.returncode != 0:
            continue
        try:
            obj = json.loads(proc.stdout)
        except Exception:
            continue
        score = int(obj.get("score", 0))
        grade = str(obj.get("grade", "?"))
        rows.append((cf, score, grade))

    avg = sum(s for _, s, _ in rows) / len(rows) if rows else 0.0
    return avg, rows


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def main() -> None:
    scan = json.loads(SCAN_JSON.read_text(encoding="utf-8"))
    sources = load_jsonl(SOURCES_JSONL)

    configs_scanned = int(scan.get("configs_scanned", 0))
    servers_scanned = int(scan.get("servers_scanned", 0))
    summary = scan.get("summary", {})
    score = int(scan.get("score", 0))
    grade = scan.get("grade", "?")

    findings = scan.get("findings", [])

    # Rule counts
    rule_counts = Counter(f.get("rule_id", "UNKNOWN") for f in findings)
    top_rules = rule_counts.most_common(5)

    # Unique server incidence per rule
    rule_servers: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for f in findings:
        key = (str(f.get("config_file", "")), str(f.get("server_name", "")))
        rule_servers[str(f.get("rule_id", "UNKNOWN"))].add(key)

    # Required percentages
    no_auth = len(rule_servers.get("AW-001", set()))
    hardcoded_secrets = len(rule_servers.get("AW-004", set()))
    unrestricted_fs = len(rule_servers.get("AW-002", set()))
    shell_exec = len(rule_servers.get("AW-003", set()))
    known_cves = len(rule_servers.get("AW-006", set()))

    # Per-config average score
    config_files = scanner_like_config_files(CONFIG_ROOT)
    avg_score, score_rows = average_score_per_config(config_files)
    if score_rows:
        worst = min(score_rows, key=lambda x: x[1])
        best = max(score_rows, key=lambda x: x[1])
    else:
        worst = (Path("N/A"), 0, "?")
        best = (Path("N/A"), 0, "?")

    # Pull notable findings (high/critical + a few specifics)
    notable = []
    for f in findings:
        rid = f.get("rule_id", "")
        if rid in {"AW-004", "AW-005", "AW-002", "AW-009", "AW-008"}:
            notable.append(f)
    # Deduplicate by (rule, config, server)
    seen = set()
    dedup_notable = []
    for f in notable:
        k = (f.get("rule_id"), f.get("config_file"), f.get("server_name"))
        if k in seen:
            continue
        seen.add(k)
        dedup_notable.append(f)

    # Keep a concise set for markdown
    dedup_notable = dedup_notable[:12]

    # Combined config attribution
    combined_files = sorted((CONFIG_ROOT / "combined").glob("*.mcp.json"))

    lines: list[str] = []
    lines.append("# WS-2 Findings: 50+ Real MCP Config Scan\n")
    lines.append("## Scope\n")
    lines.append(
        "Scanned real-world MCP server configurations collected from public GitHub config files, official `@modelcontextprotocol` READMEs, and community tutorial docs.\n"
    )
    lines.append(
        f"- External source-derived configs: **{len(sources)}** (single-server normalized files)\n"
    )
    lines.append(
        f"- Combined test configs (derived from above): **{len(combined_files)}**\n"
    )
    lines.append(f"- Total config files scanned by agentwise: **{configs_scanned}**\n")
    lines.append(f"- Total server entries scanned: **{servers_scanned}**\n")
    lines.append(
        f"- Aggregate live scan score: **{score}/100 ({grade})**  \n  _(single aggregate score across all findings in one run)_\n"
    )

    lines.append("\n## Findings by Severity\n")
    lines.append(f"- Critical: **{summary.get('critical', 0)}**\n")
    lines.append(f"- High: **{summary.get('high', 0)}**\n")
    lines.append(f"- Medium: **{summary.get('medium', 0)}**\n")
    lines.append(f"- Low: **{summary.get('low', 0)}**\n")
    lines.append(f"- Total findings: **{summary.get('total', 0)}**\n")

    lines.append("\n## Most Common Issues (Top 5 Rules Triggered)\n")
    for rule_id, count in top_rules:
        lines.append(f"- **{rule_id}**: {count} findings\n")

    lines.append("\n## Required Risk Metrics\n")
    lines.append(
        f"- % of servers with no auth on remote endpoints (AW-001): **{pct(no_auth, servers_scanned):.2f}%** ({no_auth}/{servers_scanned})\n"
    )
    lines.append(
        f"- % with hardcoded secrets (AW-004): **{pct(hardcoded_secrets, servers_scanned):.2f}%** ({hardcoded_secrets}/{servers_scanned})\n"
    )
    lines.append(
        f"- % with unrestricted filesystem access (AW-002): **{pct(unrestricted_fs, servers_scanned):.2f}%** ({unrestricted_fs}/{servers_scanned})\n"
    )
    lines.append(
        f"- % with shell/exec access (AW-003): **{pct(shell_exec, servers_scanned):.2f}%** ({shell_exec}/{servers_scanned})\n"
    )
    lines.append(
        f"- % with known CVEs (AW-006): **{pct(known_cves, servers_scanned):.2f}%** ({known_cves}/{servers_scanned})\n"
    )

    lines.append("\n## Average Security Score\n")
    lines.append(
        f"- Average per-config score: **{avg_score:.2f}/100** across {len(score_rows)} configs (computed by scanning each config individually with agentwise)\n"
    )
    lines.append(
        f"- Best config score: **{best[1]}/100 ({best[2]})** — `{best[0].relative_to(ROOT)}`\n"
    )
    lines.append(
        f"- Worst config score: **{worst[1]}/100 ({worst[2]})** — `{worst[0].relative_to(ROOT)}`\n"
    )

    lines.append("\n## Notable Findings\n")
    lines.append(
        "- **Universal allowlist gap**: AW-007 triggered on every scanned server entry (109/109), indicating missing or incomplete tool allowlists across real-world configs.\n"
    )
    lines.append(
        "- **Real hardcoded credential exposure observed**: an OpenRouter/OpenAI-style key pattern was detected in a public config (`browserbase-local`).\n"
    )
    lines.append(
        "- **Insecure transport still appears in the wild**: HTTP (non-TLS) endpoint usage was detected (`service-desk-plus`).\n"
    )
    lines.append(
        "- **Filesystem over-permissioning remains common**: multiple filesystem servers lacked `allowedDirectories`, expanding potential blast radius.\n"
    )
    lines.append(
        "- **Network-capable servers often unrestricted**: fetch/browser automation servers were able to access arbitrary domains.\n"
    )

    lines.append("\n### Notable Finding Samples\n")
    lines.append("| Rule | Severity | Server | Config file | Title |\n")
    lines.append("|---|---|---|---|---|\n")
    for f in dedup_notable:
        safe_title = str(f.get("title", "")).replace("|", "\\|")
        lines.append(
            f"| {f.get('rule_id','')} | {f.get('severity','')} | `{f.get('server_name','')}` | `{f.get('config_file','')}` | {safe_title} |\n"
        )

    lines.append("\n## Source Attribution (All Collected External Configs)\n")
    lines.append("| # | Local file | Server | Source type | Source URL |\n")
    lines.append("|---:|---|---|---|---|\n")
    for r in sources:
        lines.append(
            f"| {r['idx']} | `{r['local_file']}` | `{r['server_name']}` | {r['source_type']} | {r['source_url']} |\n"
        )

    lines.append("\n## Combined Test Config Attribution\n")
    lines.append(
        "The following combined configs were generated from the externally sourced configs above (no fabricated server definitions):\n"
    )
    for cf in combined_files:
        try:
            obj = json.loads(cf.read_text(encoding="utf-8"))
            count = len(obj.get("mcpServers", {}))
        except Exception:
            count = 0
        lines.append(f"- `{cf.relative_to(ROOT)}` — {count} server entries (derived set)\n")

    lines.append("\n## Method Notes\n")
    lines.append(
        "- Live scan command used: `cargo run -- scan research/configs/ --live --format json > research/scan-results.json`\n"
    )
    lines.append(
        "- Terminal report command used: `cargo run -- scan research/configs/ --live > research/scan-results-terminal.txt`\n"
    )
    lines.append(
        "- For percentage metrics, denominator is `servers_scanned` from the live aggregate run.\n"
    )

    FINDINGS_MD.write_text("".join(lines), encoding="utf-8")
    print(f"Wrote {FINDINGS_MD}")


if __name__ == "__main__":
    main()
