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
npm run check
npm test
```

Add regression coverage for policy semantics, DNS wire behavior, authentication, or persistence changes. Avoid tests that merely duplicate static presentation. Do not check in databases, credentials, personal queries, generated binaries, or agent instruction/context files. Update the security/operations docs when changing a trust boundary.

The project uses Rust 2024, Tokio/Axum, SQLite, and a buildless embedded web console. See `src/policy.rs` for decisions, `src/dns.rs` for DNS transport, `src/api.rs` for management, `src/browser.rs` and `src/browser_api.rs` for browser policy/enrollment, `src/bin/wtp-native.rs` for OS identity, `extension/` for browser enforcement, `crates/endpoint/` for signed network enforcement, `src/endpoint_api.rs` for device management, and `web/` for the frontend.

Contributions are licensed under AGPL-3.0-or-later. Preserve attribution for external lists and assets.

Endpoint changes also require `python3 scripts/linux-integration.py` (Docker; isolated kernel enforcement) and the native plan checks in CI. Never test firewall activation on a developer workstation or shared CI runner. Native Windows/macOS acceptance belongs on disposable managed VMs with console recovery. See the endpoint and signing guides.
