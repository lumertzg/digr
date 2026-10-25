# AGENTS.md

## Development

- Use the mise-managed Rust nightly toolchain.
- Run `mise exec -- cargo fmt --check`, `mise exec -- cargo clippy --all-targets -- -D warnings`, and `mise exec -- cargo test` before finishing code changes.

## Style

- Keep the implementation small and separate CLI parsing, DNS queries, and terminal I/O.
- Use a single blank line between logical steps within functions: setup, validation, loops, state updates, and final results.
- Comments should explain why, not what.
