<p align="center"><img src="web/favicon.svg" width="72" alt="What's the Point logo"></p>
<h1 align="center">what’s the point</h1>
<p align="center"><strong>Your network. Your rules. That’s the point.</strong></p>
<p align="center">
  <a href="https://github.com/CharlesDerek/whatsthepoint/actions/workflows/ci.yml"><img src="https://github.com/CharlesDerek/whatsthepoint/actions/workflows/ci.yml/badge.svg" alt="Build and test"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-green" alt="AGPL 3.0 or later"></a>
  <img src="https://img.shields.io/badge/built_with-Rust-orange" alt="Built with Rust">
</p>

A self-hosted DNS web filter for Linux, macOS, and Windows, with an embedded, authenticated management console. One Rust executable. No browser extension, frontend build step, external database, or subscription required.

It started with a joke: if a half-working browser extension can become a billion-dollar filtering company, what happens if we actually make the filter work?

We are starting with working software. The billion dollars are tracked separately.

![The console showing four actual test DNS requests](docs/console.png)

**v0.1 is a usable DNS filtering foundation, not an enterprise endpoint security suite.** It filters domain lookups made through it. It does not inspect page content, block URL paths, install kernel drivers, or prevent a device owner from changing DNS or using a VPN.

## What works

- DNS over UDP **and TCP**, IPv4 or IPv6 listeners, configurable client CIDR allowlists.
- Encrypted upstream DNS using [RFC 8484 DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc8484), certificate validation, bootstrap IPs, sequential failover, and no plaintext fallback.
- A bounded TTL cache with live policy evaluation on every request, including cached answers.
- Domain and subdomain blocking, international domain normalization, explicit allow overrides, and CNAME/HTTPS/SVCB target checks in returned answers.
- [HaGeZi](https://github.com/hagezi/dns-blocklists) Light and Normal feed installation, daily refresh, last-good-copy retention, and atomic hosts/domain list imports.
- A responsive console with live traffic metrics, searchable query history, policy diagnostics, client activity, and administrator audit history.
- Argon2id password storage, hashed server-side sessions, HttpOnly/SameSite cookies, CSRF protection, strict Host/Origin checks, and login throttling.
- Local SQLite storage, log retention limits, optional query logging, graceful shutdown, and local password recovery.
- Native CI builds and tests on Linux x64, Windows x64, macOS Apple Silicon, and macOS Intel.

## Start in three commands

Install a current stable Rust toolchain (minimum 1.91; newer dependencies may eventually require an update), then:

```sh
cargo build --release --locked
./target/release/wtp init
./target/release/wtp serve
```

On Windows, use `.\target\release\wtp.exe` in place of `./target/release/wtp`.

Open **http://127.0.0.1:8080**, sign in with `admin` and the password you chose, then open **Blocklists → Add protection**. There is no default password. The initial policy contains only `blocked.test`, a reserved test domain; a community feed is downloaded only when you install it.

The default DNS listener is **127.0.0.1:5354**, deliberately unprivileged so you can try it before changing system networking:

```sh
dig @127.0.0.1 -p 5354 blocked.test       # NXDOMAIN: blocked locally
dig @127.0.0.1 -p 5354 example.com        # Resolved using encrypted upstream
dig +tcp @127.0.0.1 -p 5354 blocked.test  # TCP works too
```

These commands test the resolver; they do not change your system DNS. To filter normal browsing, configure port 53 and point your device/router at it. See the [platform setup and rollback guide](docs/operations.md).

## Configuration

```sh
./target/release/wtp config > wtp.toml
./target/release/wtp --config wtp.toml --data-dir data serve
```

`wtp.toml`, databases, logs, build artifacts, and local agent/LLM instruction files are gitignored. Pass the same `--data-dir` to `init`, `serve`, `check`, and `reset-password`. Configuration uses TOML; unknown options fail startup rather than silently doing nothing.

```toml
dns_bind = "127.0.0.1:53"
http_bind = "127.0.0.1:8080"
public_origin = "http://127.0.0.1:8080"
allowed_clients = ["127.0.0.0/8", "::1/128"]
cache_entries = 10000
query_log = true
retention_days = 7
max_log_entries = 100000

[[upstreams]]
url = "https://dns.quad9.net/dns-query"
bootstrap = "9.9.9.9:443"

[[upstreams]]
url = "https://dns.quad9.net/dns-query"
bootstrap = "149.112.112.112:443"
```

The default [Quad9 secure service](https://quad9.net/service/service-addresses-and-features/) also blocks known threats and validates DNSSEC upstream. Local allow rules cannot override blocks imposed by an upstream provider. WTP trusts the configured DoH resolver's validation; it is not an independent DNSSEC validator.

For LAN use, set the DNS bind address to the server's LAN IP and explicitly add your subnet to `allowed_clients`. Configure the firewall to admit DNS only from intended clients. For IPv6, bind an IPv6 address and supply an IPv6 CIDR; do not assume an IPv6 wildcard also accepts IPv4 on every OS. One listening address is supported per instance.

For a remotely accessible console, keep its listener on loopback, terminate TLS with a reverse proxy, and set `public_origin` to its exact HTTPS origin, without a trailing slash. See [operations](docs/operations.md#remote-console).

## Rules that you can explain

1. An allow rule on the requested domain or any ancestor wins.
2. Otherwise, the nearest matching block rule or blocklist domain blocks it.
3. Otherwise, forward to the configured encrypted upstream.
4. Inspect CNAME, HTTPS, and SVCB targets in the returned answer using the same policy.

`example.com` matches `a.example.com`, but never `notexample.com` or `example.com.evil.net`. Both bare domains and `*.example.com` include the apex. Allowing a parent domain allows all its descendants, even if a child has a block rule. An unrelated blocked alias target still needs its own allow rule.

```sh
./target/release/wtp check sub.blocked.test
```

The console's **Test a domain** and the CLI `check` explain local rules only. They do not query upstreams or discover aliases. Policy changes apply on the next query arriving at WTP; existing browser/OS DNS caches and already-open connections can outlive them.

## Privacy and security

Your configuration, password hashes, sessions, policies, and query history live in your data directory. There are no analytics, remote JavaScript, external fonts, or third-party requests from the console itself. DoH queries go to your configured resolver; installed community feeds download from GitHub.

Query logs include client IPs and domain names. Set `query_log = false` to stop recording new queries. Clear existing history separately in the console. Logs are capped by age and count, with pruning every minute. The bounded log queue can drop events under load; dashboard metrics describe retained logged traffic, not billing-grade counters.

Read [the security model](SECURITY.md) before an untrusted-network deployment. WTP does not silently modify your computer's DNS, firewall, browser policy, or system services.

## Develop and verify

```sh
cargo test --locked
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
```

The console is plain HTML/CSS/JavaScript embedded at compile time. Node is only required for browser tests:

```sh
npm ci
npx playwright install chromium
npm test
```

The browser suite starts a disposable instance on HTTP port 18080 and DNS port 15354, creates a test-only account, exercises login/policy/import flows, and checks desktop/mobile rendering. It never uses your normal data directory. Rust tests cover actual UDP/TCP sockets, mocked upstream failover, cache TTLs, aliases, policy persistence, authentication, CSRF, expiry, password changes, imports, and retention.

Native CI produces downloadable `wtp` executable artifacts for each platform. A tag such as `v0.1.0` can use the release workflow to package archives with SHA-256 checksums. Release binaries are currently unsigned; macOS notarization and Windows signing are not included.

For an optional real-network check after building the release binary, run `python3 scripts/smoke.py --feed`. It creates a temporary instance, verifies live DoH resolution and downloaded feed enforcement, and removes its data afterward.

## The next points

This release uses one policy for all clients and one locally initialized administrator. We would like to add per-device policy groups, schedules, signed endpoint installers, managed OS enforcement, independent security review, and reproducible performance benchmarks. Those features are not disguised as working buttons in the console.

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md). Code is licensed under **AGPL-3.0-or-later**; external blocklists retain their own licenses. See [THIRD_PARTY.md](THIRD_PARTY.md).
