#!/usr/bin/env python3
"""WS-2 collector: gather real MCP server configs from public sources.

Outputs:
- research/configs/sources/*.mcp.json (single-server configs, one per unique server object)
- research/configs/SOURCES.jsonl
- research/configs/SOURCES.csv
- research/configs/SOURCES.md
- research/configs/combined/*.mcp.json (combined test configs)
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import requests

ROOT = Path("/Users/bwise/clawd/projects/agentwise")
RESEARCH_DIR = ROOT / "research"
CONFIG_DIR = RESEARCH_DIR / "configs"
SOURCES_DIR = CONFIG_DIR / "sources"
COMBINED_DIR = CONFIG_DIR / "combined"

ALLOWED_CONFIG_BASENAMES = {".mcp.json", "mcp.json", "claude_desktop_config.json"}


@dataclass
class SavedRecord:
    idx: int
    local_file: str
    server_name: str
    source_type: str
    source_url: str
    repository: str
    source_path: str
    query: str
    object_hash: str


class GithubCollector:
    def __init__(self, token: str) -> None:
        self.s = requests.Session()
        self.base_headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "agentwise-ws2-research",
        }
        self.saved: List[SavedRecord] = []
        self.seen_server_hashes = set()
        self.seen_source_urls = set()
        self.counter = 0
        self.counts = {"github-config": 0, "official-readme": 0, "community-tutorial": 0}

    def _request_json(self, url: str, params: Optional[dict] = None, retries: int = 4) -> dict:
        backoff = 1.0
        for attempt in range(retries):
            r = self.s.get(url, headers=self.base_headers, params=params, timeout=45)
            if r.status_code in (429, 502, 503, 504):
                time.sleep(backoff)
                backoff *= 2
                continue
            if r.status_code == 403 and "rate limit" in r.text.lower():
                reset = r.headers.get("X-RateLimit-Reset")
                if reset and reset.isdigit():
                    wait = max(1, int(reset) - int(time.time()) + 1)
                    time.sleep(min(wait, 30))
                    continue
                time.sleep(backoff)
                backoff *= 2
                continue
            r.raise_for_status()
            return r.json()
        raise RuntimeError(f"GitHub API failed after retries: {url}")

    def _request_raw(self, url: str, retries: int = 4) -> str:
        headers = dict(self.base_headers)
        headers["Accept"] = "application/vnd.github.v3.raw"
        backoff = 1.0
        for _ in range(retries):
            r = self.s.get(url, headers=headers, timeout=45)
            if r.status_code in (429, 502, 503, 504):
                time.sleep(backoff)
                backoff *= 2
                continue
            if r.status_code == 403 and "rate limit" in r.text.lower():
                reset = r.headers.get("X-RateLimit-Reset")
                if reset and reset.isdigit():
                    wait = max(1, int(reset) - int(time.time()) + 1)
                    time.sleep(min(wait, 30))
                    continue
                time.sleep(backoff)
                backoff *= 2
                continue
            r.raise_for_status()
            return r.text
        raise RuntimeError(f"GitHub raw fetch failed after retries: {url}")

    @staticmethod
    def _slug(value: str, max_len: int = 28) -> str:
        value = value.strip().lower()
        value = re.sub(r"[^a-z0-9]+", "-", value)
        value = value.strip("-")
        return (value[:max_len]).strip("-") or "x"

    @staticmethod
    def _json_blocks(markdown: str) -> Iterable[dict]:
        # Parse fenced JSON blocks that contain mcpServers.
        code_block_re = re.compile(r"```(?:json|jsonc)?\s*(\{[\s\S]*?\})\s*```", re.IGNORECASE)
        for m in code_block_re.finditer(markdown):
            block = m.group(1)
            try:
                obj = json.loads(block)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and isinstance(obj.get("mcpServers"), dict):
                yield obj

    def _save_server(
        self,
        server_name: str,
        server_obj: dict,
        source_type: str,
        source_url: str,
        repository: str,
        source_path: str,
        query: str,
    ) -> bool:
        # Keep unique server objects by canonical hash.
        canonical = json.dumps(server_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        object_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if object_hash in self.seen_server_hashes:
            return False
        self.seen_server_hashes.add(object_hash)

        self.counter += 1
        repo_slug = self._slug(repository.replace("/", "-"), max_len=30)
        server_slug = self._slug(server_name, max_len=30)
        source_slug = self._slug(source_type, max_len=14)
        filename = f"{source_slug}-{self.counter:03d}-{repo_slug}-{server_slug}.mcp.json"
        out_path = SOURCES_DIR / filename

        wrapped = {"mcpServers": {server_name: server_obj}}
        out_path.write_text(json.dumps(wrapped, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        rec = SavedRecord(
            idx=self.counter,
            local_file=str(out_path.relative_to(ROOT)),
            server_name=server_name,
            source_type=source_type,
            source_url=source_url,
            repository=repository,
            source_path=source_path,
            query=query,
            object_hash=object_hash,
        )
        self.saved.append(rec)
        self.counts[source_type] = self.counts.get(source_type, 0) + 1
        return True

    def collect_from_config_files(self, target: int = 45) -> None:
        queries = [
            "filename:claude_desktop_config.json mcpServers",
            "filename:.mcp.json mcpServers",
            "filename:mcp.json mcpServers",
            "path:.cursor/mcp.json mcpServers",
        ]

        for query in queries:
            for page in range(1, 11):
                if self.counts["github-config"] >= target:
                    return

                data = self._request_json(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 100, "page": page},
                )
                items = data.get("items", [])
                if not items:
                    break

                for item in items:
                    if self.counts["github-config"] >= target:
                        return

                    basename = item.get("name", "")
                    if basename not in ALLOWED_CONFIG_BASENAMES:
                        continue

                    raw_url = item.get("url")
                    if not raw_url or raw_url in self.seen_source_urls:
                        continue
                    self.seen_source_urls.add(raw_url)

                    try:
                        content = self._request_raw(raw_url)
                        obj = json.loads(content)
                    except Exception:
                        continue

                    mcp_servers = obj.get("mcpServers")
                    if not isinstance(mcp_servers, dict) or not mcp_servers:
                        continue

                    repo = item.get("repository", {}).get("full_name", "unknown/unknown")
                    source_path = item.get("path", "")
                    source_url = item.get("html_url", "")

                    for server_name, server_obj in mcp_servers.items():
                        if not isinstance(server_obj, dict):
                            continue
                        added = self._save_server(
                            server_name=server_name,
                            server_obj=server_obj,
                            source_type="github-config",
                            source_url=source_url,
                            repository=repo,
                            source_path=source_path,
                            query=query,
                        )
                        if added and self.counts["github-config"] >= target:
                            return

    def collect_official_readme_examples(self, target: int = 8) -> None:
        query = "repo:modelcontextprotocol/servers mcpServers claude_desktop_config.json extension:md"

        for page in range(1, 4):
            if self.counts["official-readme"] >= target:
                return
            data = self._request_json(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 100, "page": page},
            )
            items = data.get("items", [])
            if not items:
                break

            for item in items:
                if self.counts["official-readme"] >= target:
                    return

                raw_url = item.get("url")
                if not raw_url:
                    continue

                # Do NOT dedupe source URL here; same README may contain multiple blocks.
                try:
                    md = self._request_raw(raw_url)
                except Exception:
                    continue

                repo = item.get("repository", {}).get("full_name", "unknown/unknown")
                source_path = item.get("path", "")
                source_url = item.get("html_url", "")

                for obj in self._json_blocks(md):
                    mcp_servers = obj.get("mcpServers", {})
                    for server_name, server_obj in mcp_servers.items():
                        if not isinstance(server_obj, dict):
                            continue
                        added = self._save_server(
                            server_name=server_name,
                            server_obj=server_obj,
                            source_type="official-readme",
                            source_url=source_url,
                            repository=repo,
                            source_path=source_path,
                            query=query,
                        )
                        if added and self.counts["official-readme"] >= target:
                            return

    def collect_community_tutorial_examples(self, target: int = 8) -> None:
        queries = [
            'extension:md mcpServers claude_desktop_config.json tutorial',
            'extension:md mcpServers ".mcp.json" tutorial',
            'extension:md mcpServers claude_desktop_config.json "how to"',
        ]

        for query in queries:
            for page in range(1, 8):
                if self.counts["community-tutorial"] >= target:
                    return

                data = self._request_json(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 100, "page": page},
                )
                items = data.get("items", [])
                if not items:
                    break

                for item in items:
                    if self.counts["community-tutorial"] >= target:
                        return

                    repo = item.get("repository", {}).get("full_name", "")
                    if repo.startswith("modelcontextprotocol/"):
                        continue

                    raw_url = item.get("url")
                    if not raw_url:
                        continue

                    try:
                        md = self._request_raw(raw_url)
                    except Exception:
                        continue

                    source_path = item.get("path", "")
                    source_url = item.get("html_url", "")

                    for obj in self._json_blocks(md):
                        mcp_servers = obj.get("mcpServers", {})
                        for server_name, server_obj in mcp_servers.items():
                            if not isinstance(server_obj, dict):
                                continue
                            added = self._save_server(
                                server_name=server_name,
                                server_obj=server_obj,
                                source_type="community-tutorial",
                                source_url=source_url,
                                repository=repo,
                                source_path=source_path,
                                query=query,
                            )
                            if added and self.counts["community-tutorial"] >= target:
                                return

    def top_off_total(self, minimum_total: int = 50) -> None:
        if len(self.saved) >= minimum_total:
            return

        query = "mcpServers filename:.mcp.json"
        page = 1
        while len(self.saved) < minimum_total and page <= 20:
            data = self._request_json(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 100, "page": page},
            )
            items = data.get("items", [])
            if not items:
                break

            for item in items:
                if len(self.saved) >= minimum_total:
                    return
                basename = item.get("name", "")
                if basename not in ALLOWED_CONFIG_BASENAMES:
                    continue

                raw_url = item.get("url")
                if not raw_url:
                    continue
                try:
                    content = self._request_raw(raw_url)
                    obj = json.loads(content)
                except Exception:
                    continue

                mcp_servers = obj.get("mcpServers")
                if not isinstance(mcp_servers, dict):
                    continue

                repo = item.get("repository", {}).get("full_name", "unknown/unknown")
                source_path = item.get("path", "")
                source_url = item.get("html_url", "")

                for server_name, server_obj in mcp_servers.items():
                    if not isinstance(server_obj, dict):
                        continue
                    self._save_server(
                        server_name=server_name,
                        server_obj=server_obj,
                        source_type="github-config",
                        source_url=source_url,
                        repository=repo,
                        source_path=source_path,
                        query=query,
                    )
                    if len(self.saved) >= minimum_total:
                        return
            page += 1

    def write_manifests(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        jsonl_path = CONFIG_DIR / "SOURCES.jsonl"
        with jsonl_path.open("w", encoding="utf-8") as f:
            for r in self.saved:
                f.write(
                    json.dumps(
                        {
                            "idx": r.idx,
                            "local_file": r.local_file,
                            "server_name": r.server_name,
                            "source_type": r.source_type,
                            "source_url": r.source_url,
                            "repository": r.repository,
                            "source_path": r.source_path,
                            "query": r.query,
                            "object_hash": r.object_hash,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )

        csv_path = CONFIG_DIR / "SOURCES.csv"
        with csv_path.open("w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(
                [
                    "idx",
                    "local_file",
                    "server_name",
                    "source_type",
                    "source_url",
                    "repository",
                    "source_path",
                    "query",
                    "object_hash",
                ]
            )
            for r in self.saved:
                w.writerow(
                    [
                        r.idx,
                        r.local_file,
                        r.server_name,
                        r.source_type,
                        r.source_url,
                        r.repository,
                        r.source_path,
                        r.query,
                        r.object_hash,
                    ]
                )

        md_path = CONFIG_DIR / "SOURCES.md"
        with md_path.open("w", encoding="utf-8") as f:
            f.write("# WS-2 Source Attribution\n\n")
            f.write(f"Total unique server configs collected: **{len(self.saved)}**\n\n")
            f.write("## Breakdown by source type\n\n")
            for k in ["github-config", "official-readme", "community-tutorial"]:
                f.write(f"- {k}: {self.counts.get(k, 0)}\n")
            f.write("\n## Config Sources\n\n")
            f.write("| # | Local file | Server | Source type | Source URL |\n")
            f.write("|---:|---|---|---|---|\n")
            for r in self.saved:
                f.write(
                    f"| {r.idx} | `{r.local_file}` | `{r.server_name}` | {r.source_type} | {r.source_url} |\n"
                )

    def build_combined_configs(self, chunk_size: int = 12, max_files: int = 4) -> int:
        COMBINED_DIR.mkdir(parents=True, exist_ok=True)
        # Remove old combined files first.
        for old in COMBINED_DIR.glob("*.mcp.json"):
            old.unlink()

        # Load source files in saved order.
        source_paths = [ROOT / r.local_file for r in sorted(self.saved, key=lambda x: x.idx)]
        created = 0
        start = 0
        while start < len(source_paths) and created < max_files:
            subset = source_paths[start : start + chunk_size]
            if not subset:
                break
            merged: Dict[str, dict] = {}
            for p in subset:
                try:
                    obj = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    continue
                mcp = obj.get("mcpServers", {})
                if not isinstance(mcp, dict):
                    continue
                for name, cfg in mcp.items():
                    if name in merged:
                        name = f"{name}-{created+1}-{len(merged)+1}"
                    merged[name] = cfg

            if merged:
                created += 1
                out = COMBINED_DIR / f"combined-batch-{created:02d}.mcp.json"
                out.write_text(json.dumps({"mcpServers": merged}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            start += chunk_size

        return created


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        token = subprocess.check_output(["gh", "auth", "token"], text=True).strip()

    SOURCES_DIR.mkdir(parents=True, exist_ok=True)
    COMBINED_DIR.mkdir(parents=True, exist_ok=True)

    # Clean prior generated source files so run is reproducible.
    for old in SOURCES_DIR.glob("*.mcp.json"):
        old.unlink()

    c = GithubCollector(token)
    c.collect_from_config_files(target=45)
    c.collect_official_readme_examples(target=8)
    c.collect_community_tutorial_examples(target=8)
    c.top_off_total(minimum_total=50)
    c.write_manifests()
    combined_count = c.build_combined_configs(chunk_size=12, max_files=4)

    print("Collected unique configs:", len(c.saved))
    print("Breakdown:", c.counts)
    print("Combined configs created:", combined_count)
    print("Manifest:", CONFIG_DIR / "SOURCES.md")


if __name__ == "__main__":
    main()
