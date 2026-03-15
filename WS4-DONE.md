# WS-4 QA & Security Gate Report

Date: 2026-03-15
Project: `/Users/bwise/clawd/projects/agentwise`
Artifacts: `ws4-logs/`

## 1) Build quality

### Commands run
- `cargo build --release`
- `cargo test`
- `cargo clippy -- -D warnings`

### Results
- Build: **PASS** (exit 0)
- Tests: **PASS** (exit 0)
- Clippy (`-D warnings`): **PASS** (exit 0)
- Warnings in build/test/clippy logs: **none found**

### Test count / pass rate
From `cargo test` output:
- Unit tests: **129 passed**, 0 failed
- Integration tests: **24 passed**, 0 failed
- **Total: 153/153 passed (100%)**

## 2) Release binary size

- Binary: `target/release/agentwise`
- Size: **4,244,464 bytes** (~**4.0 MB**)

## 3) `cargo audit` results

### Commands run
- `cargo install cargo-audit`
- `cargo audit`

### Results
- `cargo-audit` install: **PASS** (already installed, exit 0)
- `cargo audit`: **PASS** (exit 0)
- Vulnerabilities: **0 found**
- Advisory warnings: **0**

(Validated via `cargo audit --json`: `"vulnerabilities": {"found": false, "count": 0}`)

## 4) Output format validation

### Commands run
- `cargo run -- scan testdata/vulnerable-mcp.json`
- `cargo run -- scan testdata/vulnerable-mcp.json --format json`
- `cargo run -- scan testdata/vulnerable-mcp.json --format sarif`
- `cargo run -- scan testdata/clean-mcp.json`
- `cargo run -- scan testdata/project/`

### Results
- Terminal vulnerable: **PASS** (exit 0) — findings rendered
- JSON vulnerable: **PASS** (exit 0)
- SARIF vulnerable: **PASS** (exit 0)
- Clean config: **PASS** (exit 0)
- Project config: **PASS** (exit 0)

### JSON/SARIF validity checks
- Raw `cargo run` output includes cargo preamble lines (`Finished ...`, `Running ...`), so piping raw output directly to `python3 -m json.tool` fails.
- Extracted payload from first `{` validates successfully for both JSON and SARIF.
- Also validated cleanly using:
  - `cargo run --quiet -- scan ... --format json | python3 -m json.tool`
  - `cargo run --quiet -- scan ... --format sarif | python3 -m json.tool`

## 5) `--fail-on` behavior

### Commands run
- `cargo run -- scan testdata/clean-mcp.json --fail-on critical`
- `cargo run -- scan testdata/vulnerable-mcp.json --fail-on critical`
- `cargo run -- scan testdata/vulnerable-mcp.json --fail-on high`

### Results
- Clean + `--fail-on critical`: **Exit 0** ✅ (expected)
- Vulnerable + `--fail-on critical`: **Exit 1** ✅ (expected)
- Vulnerable + `--fail-on high`: **Exit 1** ✅ (expected)

## 6) `--live` and `--supply-chain`

### Commands run
- `cargo run -- scan testdata/vulnerable-mcp.json --live`
- `cargo run -- scan testdata/vulnerable-mcp.json --supply-chain`
- `cargo run -- scan testdata/vulnerable-mcp.json --live --supply-chain`

### Results
- All three commands: **PASS** (exit 0)
- `--live` output includes OSV/EPSS enrichment and summary line:
  - `Live CVE check: queried OSV for 1 package (0 new vulnerabilities found)`
- `--supply-chain` adds expected supply-chain findings (AW-011, AW-012)
- Combined mode (`--live --supply-chain`) includes both behaviors

## 7) `agentwise update`

### Command run
- `cargo run -- update`

### Result
- **PASS** (exit 0)
- Output: `Updated: 29 vulnerabilities for 5 packages (cached at /Users/bwise/.agentwise/cve-cache.json)`

## 8) Meta-scan on project fixtures

### Command run
- `cargo run -- scan testdata/ --live --format json`

### Result
- **PASS** (exit 0)
- JSON payload: valid
- Scan summary:
  - `configs_scanned: 1`
  - `servers_scanned: 1`
  - `summary.total: 1` (AW-007 on `testdata/project/.mcp.json`)

Note: directory auto-discovery scanned only supported config filenames in `testdata/`; this did **not** include `vulnerable-mcp.json` / `clean-mcp.json` by name.

## 9) README review

File reviewed: `README.md`

### CLI examples
- Core CLI examples were exercised via equivalent `cargo run -- ...` commands.
- Command syntax and behavior are correct.
- `--fail-on high` exits non-zero when high+ findings exist (expected CI-gating behavior).

### Install instructions accuracy
- `cargo install agentwise`: **currently fails** (`crate not found` on crates.io).
- Pre-built installer path exists (`install.sh` URL is reachable), but `releases/latest` currently returns 404 (no published release), so install flow is not currently usable.
- Homebrew section is marked “coming soon” (acceptable as roadmap text).

### Links / badges / versions
- GitHub links in README (`repo/actions/stargazers/raw install.sh`) returned HTTP 200.
- Crates page link (`https://crates.io/crates/agentwise`) returns **404**.
- Badge URL formats are valid.
  - CI/stars/license badges resolve.
  - crates badge resolves but renders **"not found"** (crate unpublished).
- Version references are consistent with `Cargo.toml` (`0.1.0`).

### Additional README issue found
- GitHub Action example uses `brandonwise/agentwise-action@v1`, but that repo path returns 404.
- This repo already contains `action.yml`; expected action reference is likely `brandonwise/agentwise@v1` (once tag/release strategy is in place).

## 10) `install.sh` verification

File reviewed: `install.sh`

### Checks
- `bash -n install.sh`: **PASS**
- `sh -n install.sh`: **PASS**
- URL construction points to correct repo (`brandonwise/agentwise`): **PASS**
- Error handling presence: **PASS** (`set -eu`, `die()`, explicit checks around downloads/checksums/extract/install)

### Runtime error-path check
- Ran with non-existent version (`AGENTWISE_VERSION=0.0.0`) to validate failure handling.
- Script failed cleanly with explicit message indicating failed archive download URL.

## Issues found & recommended fixes

1. **README install from crates.io is currently inaccurate**
   - Issue: crate not published (`cargo install agentwise` fails).
   - Fix: either publish crate first, or mark crates.io install as “coming soon” until published.

2. **README pre-built installer assumes GitHub release exists**
   - Issue: `releases/latest` returns 404 right now.
   - Fix: publish initial tagged release artifacts before advertising installer, or add note that release binaries are not yet available.

3. **README GitHub Action reference appears wrong**
   - Issue: `brandonwise/agentwise-action@v1` repo path does not exist.
   - Fix: update docs to the correct action source (likely `brandonwise/agentwise@v1`), and ensure tags/releases support that usage.

4. **JSON/SARIF validation nuance in docs/QA scripts**
   - Issue: `cargo run` prepends build/run lines that break raw JSON piping.
   - Fix: use `cargo run --quiet -- ...` or invoke built binary directly when validating JSON/SARIF in CI examples.

## OVERALL: **FAIL** (release-readiness/documentation gate)

Reasoning:
- **Code quality/security checks passed** (build/test/clippy/audit/update/feature flags all good).
- However, **user-facing install and integration documentation is not fully accurate yet**:
  - crates.io install path not available,
  - release-based install currently unavailable,
  - GitHub Action README reference appears broken.

If those doc/distribution issues are corrected, the implementation itself is in strong shape and should pass this gate.
