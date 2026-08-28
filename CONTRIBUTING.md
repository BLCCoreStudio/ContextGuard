# Contributing to ContextGuard

Thanks for helping improve ContextGuard.

## Development

Requirements:

- Rust 1.74 or newer
- Git

Before opening a pull request, run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

## Contribution guidelines

- Keep redaction rules deterministic and explainable.
- Add tests for every new detection or redaction rule.
- Prefer false-positive-aware rules over broad destructive matching.
- Do not add telemetry, remote uploads, or hidden network behavior.
- Do not include real credentials, secrets, private keys, or personal data in tests or examples.
- Document security limitations instead of overstating protection.

## Pull requests

Keep changes focused. Describe what is detected, what is redacted, expected false-positive risks, and how the behavior was tested.
