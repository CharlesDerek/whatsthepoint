# Contributing

Help make the point sharper.

Open an issue describing the problem or propose a focused pull request. Keep DNS filtering behavior explainable, the console usable without external services, and security-sensitive defaults explicit.

Before submitting:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
npm ci
npx playwright install chromium
npm test
```

Add regression coverage for policy semantics, DNS wire behavior, authentication, or persistence changes. Avoid tests that merely duplicate static presentation. Do not check in databases, credentials, personal queries, generated binaries, or agent instruction/context files. Update the security/operations docs when changing a trust boundary.

The project uses Rust 2024, Tokio/Axum, SQLite, and a buildless embedded web console. See `src/policy.rs` for decisions, `src/dns.rs` for DNS transport, `src/api.rs` for management, and `web/` for the frontend.

Contributions are licensed under AGPL-3.0-or-later. Preserve attribution for external lists and assets.
