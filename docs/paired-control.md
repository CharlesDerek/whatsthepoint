# LAN master and paired desktop console

WTP 0.3 adds a native HTTPS listener, a paired desktop console, encrypted local
credential pools, and authenticated agent management. These controls protect the
management connection. They do not turn a MAC address into a secret or make an
administrator-owned machine tamper-proof.

## Start a LAN master

Choose this server's actual, stable LAN address and subnet prefix:

```sh
cargo build --release --locked
./target/release/wtp --data-dir data init
./target/release/wtp --data-dir data lan-init --address 192.168.1.10 --prefix 24 --output wtp.toml
./target/release/wtp --data-dir data --config wtp.toml serve
```

Open `https://192.168.1.10:8443`. `lan-init` creates a certificate with the address
as its subject alternative name, a private key, and a configuration binding HTTPS
and DNS to that LAN address. It refuses to overwrite an existing identity. Reserve
the address in DHCP or use a static address. DNS starts on port 5354; port 53 and
router/client DNS settings require a separate administrator deployment.

The generated certificate is self-signed. Transfer `data/master.crt` through a
trusted channel and trust it explicitly in managed browsers/OS certificate stores.
Never distribute `master.key` or disable certificate verification. The paired
desktop/agent pins the certificate from its invitation and needs no global CA-store
change. A network adversary's replacement invitation is not trustworthy; get the
invitation from an authenticated portal or the server's local CLI and compare the
master fingerprint through a trusted channel.

The listener accepts only TLS 1.3, **X25519MLKEM768** hybrid key exchange and
**TLS_AES_256_GCM_SHA384**. Unsupported browsers fail the handshake rather than
downgrading. Use a current Chrome/Edge build with ML-KEM support. The Rust clients
ship the compatible TLS implementation. Ordinary loopback HTTP remains available
for development. A legacy HTTPS reverse proxy can serve the browser portal, but
cannot activate paired control: that requires the native TLS listener.

Allow inbound TCP 8443 and the configured DNS port only from intended networks in
your existing firewall. `lan-init` does not change the host firewall or system DNS.
Use your platform service manager to keep `wtp serve` running. On Linux, the
[desktop launcher installer](../deploy/desktop/install-linux.py) installs the desktop
launcher; the portal itself can use the existing system service deployment or a
user service with absolute config/data paths.

## Pair and open a desktop console

1. In the web portal, open **Paired consoles → Pair a desktop**, name it, and
   download the single-use invitation. It expires after ten minutes. A console
   principal has full policy administration rights; it is not a read-only viewer.
2. Run `wtp-desktop open`. On Linux it uses Chrome's app window when installed;
   Windows uses Edge; macOS uses Chrome. A system-browser fallback is available.
   This is the same shipped web UI, backed by a local native Rust broker, not an
   Electron/Tauri build or an OS WebView.
3. Choose the invitation and a local vault passphrase of at least 12 characters.
   The master opens in the shared console. **Masters** switches saved connections;
   **Sign out** locks the in-memory pool. Close the broker process when finished
   if you also want its loopback listener stopped.

Install a Linux application-menu launcher:

```sh
python3 deploy/desktop/install-linux.py --binary target/release/wtp-desktop
```

On Windows run `wtp-desktop.exe open`; on macOS run `wtp-desktop open`. Signed release
packaging includes the binary. Native window/installer behavior on Windows/macOS
still requires acceptance testing on those platforms.

Headless enrollment is also available:

```sh
wtp --data-dir data --config wtp.toml pair-console --name "Operations desktop" --output /private/path/console-invitation.json
wtp-desktop pair --bundle /private/path/console-invitation.json
wtp-desktop list
wtp-desktop open
```

`pair-console` is local administrator recovery access, like password reset: protect
the data directory. Delete consumed invitation files. Avoid putting invitations in
source control, support tickets, or shared folders. Console credentials expire after
90 days; create a new invitation and re-pair to renew. Re-pairing replaces that
master's entry in the local pool; revoke the old principal in the portal.

Default vault locations are `~/.local/share/whatsthepoint/desktop-vault.json` on
Unix and `%LOCALAPPDATA%\whatsthepoint\desktop-vault.json` on Windows. `--vault`
overrides the location. The pool supports 128 masters and uses Argon2id (64 MiB,
three passes) and AES-256-GCM. There is no password recovery mechanism for the
local vault: revoke lost credentials, remove the inaccessible vault, and re-pair.

The renderer talks to an authenticated loopback broker. A single-use, two-minute
launch capability creates a HttpOnly/SameSite session; Host/Origin checks and CSRF
tokens protect mutations. Paired secrets stay in the native broker, not browser
storage. Local account compromise can still access broker memory or an unlocked
session. `--no-open` prints a sensitive bootstrap URL for automation; do not log or
share it in production.

## Principal and replay protocol

The master descriptor includes a random server ID, name, HTTPS origin, management
IP:port, network adapter MAC metadata, pinned certificate, and policy verification
key. SHA-256 binds that descriptor to a node's random installation ID, OS, UID/SID,
hostname and sorted MAC metadata. Empty MAC sets are allowed on virtual machines.
MACs and identity hashes are public context, not proof of possession or attestation.
Changing the master descriptor requires re-pairing; preserve its database, keys,
address and adapter identity across ordinary restarts.

Pairing proves possession of the invitation's random 256-bit secret using
HMAC-SHA-256. HKDF-SHA-256 separates authentication and encryption keys. The server atomically consumes the invitation and returns an
AES-256-GCM encrypted principal credential. Server-side credential secrets are
encrypted under a separate `control-storage.key` next to the database. Protect and
back up that key along with the database; database-only theft does not disclose the
paired secrets, while theft of both does. The policy signing key still resides in
the database and requires its own protection.

Every paired request authenticates its principal, master/device hashes, method,
path, body hash, 256-bit nonce and timestamp. Requests outside a 60-second clock
window fail. SQLite atomically records the nonce before dispatch, and duplicate
nonces fail even across restarts. Nonces remain for more than the entire replay
window and are pruned after expiry. Responses authenticate their status/body and
bind to the exact request authenticator and nonce. Keep client/server clocks synced.
TLS early data, tickets, and client session resumption are disabled. Proxies and
redirects are disabled for paired clients.

Network capture cannot replay an accepted operation. A lost response is still an
ambiguous operation: inspect current state before repeating a mutation with a new
nonce. Someone who steals a valid credential can create new authenticated requests
until it is revoked or expires. Console principals can call administrator APIs;
agent principals can only refresh their own policy and acknowledge their own
commands. Revocation blocks subsequent requests; it does not roll back an operation
already dispatched. Browser-extension profile tokens remain separate scoped bearer
credentials protected by HTTPS, with their existing rotation/revocation controls.

**Post-quantum scope:** the live channel uses the standardized ML-KEM-768 plus
X25519 hybrid exchange supplied by rustls/AWS-LC. X.509 certificates and offline
Ed25519 policy/release signatures are still classical signatures. This is hybrid
post-quantum transport confidentiality, not a claim that all signing, trust stores,
storage, or hardware are post-quantum certified. No custom KEM is implemented.

## Paired agents and remote removal

Native-TLS endpoint enrollment includes a single-use agent invitation. Install it
within ten minutes using the [endpoint installation guide](endpoint-enforcement.md).
Preflight `fetch` pins the invitation's certificate and uses the same hybrid TLS
without consuming the invitation. On first supervised start, the agent pairs, seals
its credential pool, and erases the invitation and bootstrap bearer from the
installed configuration. The server then rejects legacy bearer access for that
endpoint, including after principal revocation.

The agent vault uses AES-256-GCM with a random key in a separate administrator-only
file, bound to its endpoint/master hash. This supports unattended startup. It is
OS-permission protection, **not TPM/Keychain/DPAPI-backed key isolation**; privileged
access to both files defeats storage encryption. Protect backups accordingly.

Remote removal must be allowed in the locally protected enrollment configuration
(`allow_remote_uninstall: true`). The portal enrollment form can prepare that value,
but only the local administrator installing the config authorizes it. A downloaded
network policy cannot turn it on. The portal offers **Uninstall agent** after an
authenticated agent reports that it permits removal.

The command has one fixed operation, `uninstall`. Its Ed25519 signature binds the
endpoint, principal, node hash, sequence ID and ten-minute validity. A protected
watermark rejects repeated commands. There are no server-supplied commands, scripts,
paths, or arbitrary executable arguments. Removal requires the standard installation
paths, disables startup, rolls back owned firewall changes, removes the installed
config/binary and credential files, acknowledges completion, and revokes the agent
principal. Windows schedules executable deletion at reboot. Rollback snapshots and
the process-lock file remain for recovery; unrelated firewall rules remain intact.

The portal shows queued, delivered, accepted, failed and completed receipts. A
missing final receipt leaves completion unconfirmed; offline machines cannot be
remotely removed. A crash after accepting a command may require local recovery.
Receipts are authenticated agent reports, not independent proof that a machine is
clean. Remote removal is Linux-tested in an isolated kernel namespace; Windows/macOS
removal code remains subject to native acceptance testing.

## Validation

Run `cargo test --workspace --locked`, `npm test`, and
`python3 scripts/linux-integration.py`. Tests cover real hybrid TLS and classical-only
handshake rejection, modified requests/responses, concurrent duplicate nonces,
restart persistence, single-use invitations, scope separation, revocation, encrypted
vault failures, the desktop's shared portal, and actual Linux pairing/enforcement/
remote uninstall with preservation of an unrelated firewall table.

Protocol references: [rustls defaults](https://docs.rs/rustls/latest/rustls/manual/_05_defaults/),
[AWS-LC provider](https://docs.rs/rustls/latest/src/rustls/crypto/aws_lc_rs/mod.rs.html),
and [NIST FIPS 203 ML-KEM](https://csrc.nist.gov/pubs/fips/203/final).
