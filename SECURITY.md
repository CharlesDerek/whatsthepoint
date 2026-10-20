# Security model

WTP 0.1 is new software without an independent security audit. The DNS service is designed for trusted local/LAN clients, and the management console is an administrative interface.

## Trust boundaries

- The account that owns the data directory can read traffic and recover/change credentials. Disk encryption and OS permissions are the operator's responsibility.
- The configured upstream sees DNS questions. TLS authenticates it, bootstrap IPs avoid resolver recursion, and client EDNS options such as ECS are stripped.
- Explicit CIDR allowlists restrict who can ask the resolver questions. IPv4 and IPv6 need deliberate configuration. Do not expose DNS to the public internet.
- Administrator access can change every policy. There is one administrator established by the CLI, without RBAC, SSO, MFA, or account enrollment.
- Feed downloads are restricted to built-in HTTPS presets, without redirects or arbitrary URL fetch endpoints. Feeds are size-bounded, strictly parsed, and replaced transactionally. HTTPS authenticates the source; feeds do not have independent content signatures.
- The console binds loopback by default. Remote operation needs an HTTPS reverse proxy. Host and Origin checks, custom mutation headers, session CSRF tokens, CSP, SameSite cookies, and no CORS grants protect browser-facing boundaries.
- Passwords are stored with Argon2id and random salts. Sessions are random 256-bit tokens stored as SHA-256 hashes, expire after eight hours, and are revoked on logout or password reset.

## Resource limits and data

DNS has bounded concurrency (256 UDP requests, 128 TCP connections), TCP read deadlines, request size limits, a bounded response cache, and a 4,096-entry query-log queue. Under overload requests may be dropped and query logs may omit events. This is not an internet-facing DDoS mitigation system.

The query log retains at most the configured age/count after minute-by-minute cleanup; bursts can exceed the count between cleanups. Deleted SQLite rows are not guaranteed securely erased from storage or backups. Audit history retains the latest 10,000 events.

Blocking replies clear authentication flags rather than pretending to be DNSSEC-signed answers. The resolver trusts the upstream's DNSSEC results. Negative responses are not cached locally. Allowed responses cache for at most one hour and never beyond their shortest record TTL.

Client-side caches can keep old answers. Long-lived connections are not terminated by a new rule. Local allows cannot remove upstream provider blocks.

## Reporting

Dependency scans run in CI. The sole audit exception is `RUSTSEC-2023-0071`: SQLx's optional MySQL dependency adds `rsa` to the lockfile, but neither MySQL nor RSA is enabled or compiled into WTP. CI checks the active dependency graph and fails if that assumption changes. No DNS/cache advisories are suppressed.

If GitHub private vulnerability reporting is enabled, use the repository's **Security → Report a vulnerability** form. Otherwise, open an issue requesting a private contact without including exploit details, credentials, or private query logs. Private reporting is a repository setting and is not automatically enabled by this file.

Do not submit production databases, session cookies, or real user browsing histories in issues. Include the version, platform, minimal reproduction, and sanitized logs.
