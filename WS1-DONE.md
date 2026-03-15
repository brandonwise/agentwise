# WS-1 Release Engineering — Completed

## ✅ Task 1: Cross-compile CI release workflow
Created `.github/workflows/release.yml` with:

- Trigger on tag pushes matching `v*`
- Build matrix for:
  - `linux-amd64` (`x86_64-unknown-linux-gnu`)
  - `linux-arm64` (`aarch64-unknown-linux-gnu`)
  - `macos-amd64` (`x86_64-apple-darwin`)
  - `macos-arm64` (`aarch64-apple-darwin`)
  - `windows-amd64` (`x86_64-pc-windows-msvc`)
- Cross-compile support for Linux ARM64 via `gcc-aarch64-linux-gnu`
- Packaging artifacts as:
  - `agentwise-{version}-{target}.tar.gz` (Unix)
  - `agentwise-{version}-{target}.zip` (Windows)
- Artifact upload via `actions/upload-artifact@v4`
- SHA256 generation into `agentwise-{version}-checksums.txt`
- GitHub release publication via `softprops/action-gh-release@v2` with all artifacts attached

## ✅ Task 2: Homebrew tap scaffold
Created new tap structure at:
- `/Users/bwise/clawd/projects/homebrew-tap/Formula/agentwise.rb`
- `/Users/bwise/clawd/projects/homebrew-tap/README.md`

Formula details:
- Uses GitHub Release URLs for architecture-specific downloads
- Includes template `version` and `sha256` placeholders for first release
- Includes test block validating `agentwise --version`

README includes:
- `brew tap brandonwise/tap`
- `brew install agentwise`
- Release update checklist for version + checksums

## ✅ Task 3: install.sh verification/rewrite
Rewrote `install.sh` to:

- Support Linux + macOS only (clean failure elsewhere)
- Detect OS/architecture and map to release targets
- Download release archive + checksum file from GitHub Releases
- Verify SHA256 before install
- Install to `/usr/local/bin` when possible, fallback to `~/.local/bin`
- Support `sudo` path when required
- Emit clear, actionable error messages
- Support optional `AGENTWISE_VERSION` override

## ✅ Task 4: crates.io prep
Validated Cargo metadata in `Cargo.toml`:
- `description`, `license`, `repository`, `readme`, `keywords`, `categories` present

Added `include` list in `Cargo.toml` to keep package contents focused (exclude unnecessary project files).

Verified package contents:
- `cargo package --list --allow-dirty`
- `cargo package --allow-dirty`

Result: package verification succeeded.

## ✅ Task 5: build/test/lint + commit
Executed successfully:
- `cargo build`
- `cargo test`
- `cargo clippy -- -D warnings`

Committed in `agentwise` repo with message:
- `ci: add release workflow, homebrew tap, and install script`

No push performed.
