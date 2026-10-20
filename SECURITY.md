# Security model

WTP 0.2 is new software without an independent security audit. The DNS service is designed for trusted local/LAN clients, and the management console is an administrative interface.

## Trust boundaries

- The account that owns the data directory can read traffic and recover/change credentials. Disk encryption and OS permissions are the operator's responsibility.
- The configured upstream sees DNS questions. TLS authenticates it, bootstrap IPs avoid resolver recursion, and client EDNS options such as ECS are stripped.
- Explicit CIDR allowlists restrict who can ask the resolver questions. IPv4 and IPv6 need deliberate configuration. Do not expose DNS to the public internet.
- Administrator access can change every policy. There is one administrator established by the CLI, without RBAC, SSO, or MFA. Browser profile enrollment creates scoped endpoint credentials, not additional administrators.
- Feed downloads are restricted to built-in HTTPS presets, without redirects or arbitrary URL fetch endpoints. Feeds are size-bounded, strictly parsed, and replaced transactionally. HTTPS authenticates the source; feeds do not have independent content signatures.
- The console binds loopback by default. Remote operation needs an HTTPS reverse proxy. Host and Origin checks, custom mutation headers, session CSRF tokens, CSP, SameSite cookies, and no CORS grants protect administrator browser boundaries. The separate `/agent/` routes accept bearer credentials and extension origins; administrator cookies cannot authorize them.
- Passwords are stored with Argon2id and random salts. Sessions are random 256-bit tokens stored as SHA-256 hashes, expire after eight hours, and are revoked on logout or password reset.

## Resource limits and data

DNS has bounded concurrency (256 UDP requests, 128 TCP connections), TCP read deadlines, request size limits, a bounded response cache, and a 4,096-entry query-log queue. Under overload requests may be dropped and query logs may omit events. This is not an internet-facing DDoS mitigation system.

The query log retains at most the configured age/count after minute-by-minute cleanup; bursts can exceed the count between cleanups. Deleted SQLite rows are not guaranteed securely erased from storage or backups. Audit history retains the latest 10,000 events.

Blocking replies clear authentication flags rather than pretending to be DNSSEC-signed answers. The resolver trusts the upstream's DNSSEC results. Negative responses are not cached locally. Allowed responses cache for at most one hour and never beyond their shortest record TTL.

Client-side caches can keep old answers. DNS/browser rules do not terminate arbitrary long-lived application connections. Endpoint firewall behavior is described separately below. Local allows cannot remove upstream provider blocks.

## Browser and desktop trust boundaries

The browser extension has HTTP(S) host access, declarative network rules, content
scripts, and native messaging. Scoped profile tokens cannot call administrator APIs.
They are hashed on the server, shown once at enrollment/rotation, and revocable.
Extension local/managed storage is restricted to trusted extension contexts.
Messages from content scripts cannot issue navigation permits or read credentials.
Remote portal connections require HTTPS; redirects are rejected to avoid forwarding
a bearer token. A compromised extension, browser, or OS account can steal a token
or falsify category/identity reports. Native UID/SID matching is not remote device
attestation or proof that a user cannot bypass the browser.

Top-level GET requests are gated with exact-URL, tab-scoped permits. DNS blocks form
a baseline that browser allows cannot weaken. Non-GET top-level navigations, frames,
and plugin objects are blocked; ordinary allowed-page subresources are not deeply
inspected. Content categorization occurs after ordinary page loading, so it cannot
promise to prevent scripts from executing. Reader mode fetches HTML without cookies
or redirects and renders only reconstructed text and checked links under a restrictive
CSP. It has a 1 MB fetch cap and timeouts. The server never fetches arbitrary page URLs.

Browser events obey `query_log` and age/count retention independently of DNS events;
URLs are stored without queries/fragments. Page paths, profile names, and category
labels may still be sensitive. No raw page text is stored in decision history.
The extension sends URLs and category evidence to the configured portal. The native
helper reports the OS identity of its launching process, and supports no privileged
operation or caller-supplied command.

Managed storage, force-installation, disabled incognito/guest profiles, and protected
native-host registration need an external administrator deployment. The provided
policy template is not an installed policy. The separate privileged endpoint agent
uses nftables, Windows Firewall, or PF; no custom driver or hardware attestation is
shipped. See [endpoint enforcement](docs/endpoint-enforcement.md) for validated scope.

## Endpoint enforcement boundary

Signed Ed25519 network policies have bounded lifetimes and bind endpoint ID, OS,
revision, and rule contents. Endpoints pin a public key and management destination;
protected local watermarks reject policy rollback. The portal's signing secret lives
in its database, so database theft compromises policy authority. Release and CRX
keys are separate. Endpoint bearer credentials are hashed and cannot administer the
portal. Device status remains self-reported and can be forged by a stolen credential.

The privileged supervisor uses validated typed IP/port/interface values, invokes
fixed platform executables without a shell, and restricts writes to protected state.
It repairs drift and expires policies to management-only quarantine. Polling, platform
command failures, and service startup create timing limits; this is not a guarantee
against root, local administrators, a modified kernel/browser, or alternate OS boots.
Local clock checks have a 30-second tolerance. Do not permit ordinary users to alter
agent config, binaries, state, trust stores, browser policy, or service definitions.

Network enforcement permits only approved destinations/interfaces plus loopback and
address-discovery exceptions. It cannot distinguish a VPN, DoH resolver, tunnel,
malware service, or unrestricted proxy on an explicitly approved IP:port. General
browsing therefore needs a controlled gateway or curated destination list. It does
not inspect arbitrary application TLS or provide application allowlisting. Windows
uses exclusive firewall management and rejects conflicting nonlocal allows; macOS
requires first-anchor PF control and flushes device-wide states on changes. Linux
owns only its table. Native Windows/macOS activation and reboot acceptance remain
unverified in this Linux workspace. Independent security review is still required.

[Release signing](docs/release-signing.md) documents trusted-key bootstrap, signed
archive verification, Authenticode, Developer ID/notarization, and extension signing.
No production keys, publisher identities, deployed update feed, or automatic
privileged binary updater are supplied.

## Reporting

Dependency scans run in CI. The sole audit exception is `RUSTSEC-2023-0071`: SQLx's optional MySQL dependency adds `rsa` to the lockfile, but neither MySQL nor RSA is enabled or compiled into WTP. CI checks the active dependency graph and fails if that assumption changes. No DNS/cache advisories are suppressed.

If GitHub private vulnerability reporting is enabled, use the repository's **Security → Report a vulnerability** form. Otherwise, open an issue requesting a private contact without including exploit details, credentials, or private query logs. Private reporting is a repository setting and is not automatically enabled by this file.

Do not submit production databases, session cookies, or real user browsing histories in issues. Include the version, platform, minimal reproduction, and sanitized logs.
