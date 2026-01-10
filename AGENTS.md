# Repository Guidelines

## Project Structure & Module Organization
- `src/` contains the Rust server runtime, CLI parsing, tarball loading, TLS, and script engine.
- `sdk/` holds the embedded C header (`zeroserve.h`) used by BPF scripts.
- `examples/` contains sample scripts and usage snippets.
- `tools/` provides helper utilities (e.g., `simpleproxy.py`).

## Build, Test, and Development Commands
- `cargo build` — compile the server binary.
- `cargo run -- --addr 0.0.0.0:8080 site.tar` — run the server against a tarball.
- `cargo run -- --pack . > site.tar` — pack the current directory into a tarball (compiles scripts).
- `cargo run -- --dump-sdk > zeroserve.h` — print the embedded SDK header.
- `killall -SIGHUP zeroserve` — trigger hot-reload of the tarball and TLS files.

## Coding Style & Naming Conventions
- Follow standard Rust style and keep modules small and focused; prefer `snake_case` for functions/vars and `CamelCase` for types.
- Use `cargo fmt` before submitting changes that touch Rust code.
- Keep CLI flags descriptive and documented in `src/cli.rs`.

## Testing Guidelines
- No automated test suite is present. Validate changes with targeted manual checks:
  - Build: `cargo build`
  - Serve: `cargo run -- --addr 0.0.0.0:8080 site.tar`
  - Pack: `cargo run -- --pack . > site.tar`
- If you add tests, include how to run them in this document.

## Security & Configuration Tips
- TLS expects PEM files; avoid committing real keys. Use local test certs where needed.
- The pack step compiles scripts in `.zeroserve/scripts/`; only `.o` files are included in the output tarball.
