# ContextGuard

Redact secrets and sensitive project context before sharing files with AI tools.

[![CI](https://github.com/BLCCoreStudio/ContextGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/BLCCoreStudio/ContextGuard/actions/workflows/ci.yml)

> **Status:** early development / pre-release. No stable release or packaged binary is published yet.

## Why ContextGuard?

Developers increasingly paste configuration files, logs, source snippets, and repository context into AI tools. Those inputs can accidentally contain credentials, private keys, authorization headers, machine-specific paths, or other sensitive details.

ContextGuard is being built as a small, local-first filter that produces a sanitized copy before content leaves your machine.

## Current development preview

The current Rust CLI is intentionally conservative and read-only. It can currently detect or redact:

- common secret assignments such as API keys, tokens, passwords, and client secrets
- bearer authorization tokens
- common GitHub, OpenAI-style, and AWS access-key token prefixes
- PEM private-key blocks
- Linux and macOS-style home-directory identities in absolute paths

ContextGuard never modifies the source file in the current preview. `redact` writes the sanitized result to standard output.

## Build from source

Requires Rust 1.74 or newer.

```bash
git clone https://github.com/BLCCoreStudio/ContextGuard.git
cd ContextGuard
cargo build --release
```

The binary will be available at:

```text
target/release/contextguard
```

## Usage

Redact a file to standard output:

```bash
contextguard redact .env
```

Use stdin:

```bash
cat debug.log | contextguard redact -
```

Check whether any current rule matches without printing the content:

```bash
contextguard check .env
```

Exit codes for `check`:

- `0` — no current rule matched
- `2` — invalid input or usage error
- `3` — one or more potential sensitive items were found

## Example

Input:

```text
API_KEY=example-secret-value
workspace=/home/alice/projects/demo
```

Output:

```text
API_KEY=[REDACTED]
workspace=<HOME>/projects/demo
```

Examples use synthetic values only.

## Security model

ContextGuard is a defense-in-depth tool, not a proof that content is safe to share. A clean result can still contain sensitive information that no current rule recognizes. False positives and false negatives are expected during development.

The project is designed around:

- local processing
- deterministic and explainable rules
- no telemetry
- no hidden network uploads
- read-only source handling in the current preview

See [SECURITY.md](SECURITY.md) for reporting guidance and limitations.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before proposing new redaction rules.

## License

MIT License. See [LICENSE](LICENSE).

---

Built by **BLC Core Studio**.
