# Managed endpoint enforcement

WTP has three enforcement layers: DNS rules, account-specific browser rules, and a
privileged `wtp-agent` that restricts the desktop's network connections. Endpoint
policies are device-wide; browser rules still select the OS account's organization,
group, and profile policy. An extension cannot install privileged OS controls by
itself. Administrators install the endpoint agent separately.

The agent uses existing kernel enforcement: nftables on Linux, Windows Defender
Firewall on Windows, and PF on macOS. No custom kernel driver is required or shipped.
The adapters, installers, signed policy protocol, portal controls, and signing tools
are implemented. **Linux enforcement has been exercised against a real kernel in
isolated containers. Earlier Windows/macOS firewall-adapter cross-checks passed; the new control channel, native firewall activation,
reboot behavior, and trusted publisher signing still need validation on those OSes.**
Do not treat cross-compilation or a generated firewall plan as a deployment test.

## Network policy and its scope

A policy names approved physical interfaces, DNS resolver IP addresses, TCP IP:port
pairs, UDP IP:port pairs, and whether DHCP is allowed. All other outbound connections
are blocked, including unapproved DNS/DoT/DoH servers, VPN endpoints, and tunnel
interfaces. IPv4 and IPv6 are covered. Loopback, IPv6 neighbor/router discovery, and
optional DHCP are infrastructure exceptions. ARP and other link-layer traffic are
not an application control boundary. An existing local proxy can relay access to
approved destinations; loopback is not inspected.

This is a strict destination allowlist. Ordinary internet browsing requires an
approved web gateway or individually approved destinations. WTP does not implement
that gateway or decrypt every application's HTTPS. A VPN/DoH/proxy service running
on an **approved** IP:port is also reachable; shared hosting/CDNs and arbitrary web
gateways are consequently unsuitable as unrestricted exceptions. Configure the
gateway to reject CONNECT/tunnels and enforce your domain policy. Application
allowlisting, MDM, secure boot, browser force-installation, and preventing alternate
OS boots remain deployment responsibilities. No claim is made that root, a local
administrator, or a device owner with boot access cannot remove these controls.

Browser categorization and sanitized reading are described in
[browser protection](browser-protection.md). Normal interactive pages are inspected
after loading; the reader classifies text before displaying it and never executes
the source document's scripts. Neither mode is an antivirus engine.

## Signed policies and supervision

The portal generates an Ed25519 signing key once and retains it in the protected
SQLite database. Back it up with the database. Each endpoint enrollment contains a
separate bearer credential, endpoint ID, pinned public key, HTTPS origin, fixed
management IP:port, physical interfaces, and bootstrap DHCP setting. The server
stores only the endpoint token's hash; it never returns the token in device lists.
An endpoint token cannot administer the portal or act as a browser profile token.

Native-TLS enrollments use pinned hybrid post-quantum TLS and single-use pairing,
then HMAC-authenticated requests with durable replay protection. See [paired agent
control and remote removal](paired-control.md). Legacy enrollments validate TLS using
the OS CA store and connect to the pinned management IP using curl's resolver
override, so quarantine does not depend on DNS. Credentials
are supplied through curl's stdin, not command-line arguments. Redirects and proxy
environment variables are disabled. Policy signatures bind the endpoint ID, OS,
revision, timestamps, and network policy in a distinct signature domain. The agent
rejects changed bytes, incorrect keys/IDs, expired policies, rollback revisions,
reused revisions with different network contents, and clock rollback beyond its
30-second tolerance. Configuration and state must be administrator-owned and
protected. A process lock prevents two agents from sharing one state directory.

The portal issues five-minute policies. The supervisor polls about every 30 seconds
and checks firewall drift about every two seconds. A request may take up to fifteen
seconds, delaying the next check; these are polling intervals, not hard real-time
guarantees. It retains a verified cached policy while offline until expiry, then
allows only the management connection and infrastructure exceptions. The same
quarantine applies at first boot without a valid cache. Successful changes persist
the anti-rollback watermark before applying firewall rules. Invalid refreshes do
not replace the last verified policy. Keep a recovery console available for initial
activation and policy changes.

The portal reports requested revision, quarantine state, last contact, and the
agent's reported state/revision. Reports are self-reported operational evidence,
not remote attestation. A stale heartbeat means enforcement is unconfirmed. A
quarantine policy can be reported as `enforced`: the published quarantine rules
are the rules being enforced. Refresh the endpoint page to see current reports.

## Enrollment and preflight

1. Configure [native LAN HTTPS](paired-control.md) for paired agents. A legacy
   HTTPS reverse proxy still supports older bearer-token enrollments.
2. In **Endpoints → Enroll an endpoint**, enter the OS, management server IP:port,
   physical interface names, approved DNS IPs, and approved TCP/UDP destinations.
   The portal always retains the management connection. Interface changes require
   local administrator re-enrollment, because they are pinned in the config.
3. Download the enrollment JSON once and transfer it securely. Native-TLS
   invitations must be installed within ten minutes. Browser profile
   enrollment is separate. The endpoint file contains a private credential; keep it
   out of tickets, source control, and shared folders. Lost endpoint credentials
   require a new enrollment; the old endpoint can be quarantined.
4. Use a trusted agent binary to fetch and review the policy before activation:

   ```sh
   wtp-agent fetch --config /absolute/endpoint-config.json --output /absolute/policy.json
   wtp-agent plan --config /absolute/endpoint-config.json --policy /absolute/policy.json
   ```

   `fetch` reports `preview` to the portal and does not change the firewall. `plan`
   verifies the signed policy and prints the OS rules. Short-lived policies may
   need fetching again. Preview does not replace the installed anti-rollback check.

## Linux installation and rollback

Requirements: root, systemd, nftables, `/usr/bin/curl`, Python 3, and a trusted
signature-verified release. Interface names can be obtained with `ip link`.
Install only after reviewing the generated policy and arranging recovery access:

```sh
sudo sh deploy/endpoint/install-linux.sh /absolute/wtp-agent /absolute/endpoint-config.json --activate
sudo /usr/local/libexec/wtp/wtp-agent status --state-dir /var/lib/wtp-endpoint
sudo journalctl -u wtp-endpoint.service
```

The installer protects config/state, installs a root systemd supervisor limited to
`CAP_NET_ADMIN`, and establishes management-only rules in `ExecStartPre` before
`network-pre.target`. The agent atomically replaces only its `inet wtp_endpoint`
table, with an output chain at priority 100. An earlier firewall accept cannot
bypass its drop, and no blanket established-connection exception is used. Other
firewall tables may still further restrict approved traffic. Runtime deletion or
modification of the owned table is detected and repaired. Root can still stop the
service or remove the table; supervision is operational repair, not root resistance.

```sh
sudo sh deploy/endpoint/uninstall-linux.sh
```

Uninstall stops supervision and removes only the owned table. Files and anti-rollback
history remain for review. For a deliberate new enrollment, archive/remove those
managed files after uninstall; old revision history must not be silently reused.

## Windows installation and rollback

Use a dedicated managed Windows endpoint, Administrator PowerShell, a trusted
Authenticode-signed agent, and its publisher certificate thumbprint:

```powershell
.\deploy\endpoint\install-windows.ps1 -Binary C:\Release\wtp-agent.exe -Config C:\Enrollment\endpoint-config.json -PublisherThumbprint YOUR_PUBLISHER_THUMBPRINT -Activate
& "$env:ProgramFiles\WhatsThePoint\wtp-agent.exe" status --state-dir "$env:ProgramData\WhatsThePoint\Endpoint"
```

The supervisor is a SYSTEM scheduled task with startup/restart settings. Files are
restricted to SYSTEM/Administrators. Installation requires exclusive firewall
management: all profiles are enabled with inbound/outbound default block, existing
local allow rules are disabled, and WTP adds explicit destination/interface permits.
Original profile settings and local enabled-allow rule names are saved for rollback.
Nonlocal GPO/MDM allow rules and disabled-interface exemptions are rejected because
local defaults cannot override them. Resolve those conflicts in the management
system; do not deploy alongside a competing firewall policy manager. Existing block
rules continue to win. Use actual physical adapter aliases, such as `Ethernet`.

Reboot after initial activation, and validate existing-connection termination,
policy refresh, task restart, and reboot behavior in a disposable Windows VM before
rollout. The native CI job checks parsing and Rust tests; it does not activate this
policy on a shared runner. Roll back from Administrator PowerShell:

```powershell
.\deploy\endpoint\uninstall-windows.ps1
```

This restores original local profile defaults and enabled allow rules while retaining
the protected snapshot. Review later administrative changes before using an old
snapshot. The installed directories remain for deliberate inspection/removal.

## macOS installation and rollback

Requirements: root, Python 3, an Apple Developer ID signed agent, its Team ID, and a
managed Mac. The installer verifies that signing identity, rejects unsafe/custom PF
skip/include layouts, and checks existing destination paths before copying files.

```sh
sudo python3 deploy/endpoint/install-macos.py --binary /absolute/wtp-agent --config /absolute/endpoint-config.json --team-id YOURTEAMID --activate
sudo /usr/local/libexec/wtp/wtp-agent status --state-dir '/Library/Application Support/WhatsThePoint/Endpoint'
```

The installer backs up `/etc/pf.conf`, registers a first `quick` filter anchor,
validates PF syntax, enables PF if needed, and starts a root launchd supervisor.
The anchor permits approved traffic and ends in a quick block. Existing PF states
are flushed during activation and policy changes because they can bypass new rules;
this disrupts existing connections device-wide. The persisted anchor initially
blocks traffic until the agent starts. macOS runtime/MDM interactions and reboot
behavior must be tested on a real/disposable Mac. Homebrew-owned installation
parents may be rejected; use administrator-owned deployment paths rather than
making those parents writable to accommodate installation.

```sh
sudo python3 deploy/endpoint/uninstall-macos.py
```

Rollback stops launchd, flushes only the WTP anchor, removes its exact parent
registration while preserving unrelated config edits, and reloads validated PF
configuration. PF remains enabled so other protections are not silently disabled.
The original config and enrollment state remain available for recovery.

## Remote removal

Native-TLS paired agents support a fixed signed uninstall operation when the local
installer authorizes `allow_remote_uninstall`. The portal can request removal after
the agent reports that opt-in. See [authorization, receipts and recovery](paired-control.md#paired-agents-and-remote-removal).
The Linux service allows writes to its protected config, state, binary and unit
directories so it can erase enrollment secrets and remove its fixed installed files.

## Release and extension signing

[Release signing](release-signing.md) covers independent artifact verification,
Authenticode, Apple Developer ID/notarization, CRX3 signing, stable extension IDs,
and the dedicated signing workflow. No production signing keys, trusted publisher
certificates, or browser-store listing are included. Signing tools fail when required
credentials are absent; the ordinary package workflow is explicitly unsigned.
Binary updates use a verified release and administrator-controlled stop/install/start
procedure. Automatic privileged binary updates are deliberately not implemented.

## Validation

Locally executed checks on Linux:

- Rust API/security tests: enrollment, scoped tokens, CSRF, signed policies, revision
  conflicts, expiry, replay, clock rollback, management retention, and release claims.
- Chromium: HTTPS endpoint enrollment/export/edit/quarantine/restore, plus existing
  real-extension navigation, categories, sanitized reader, native identity, and
  outage/revocation tests.
- Isolated Docker network with real nftables: approved/blocked IPv4 and IPv6,
  fresh IPv6 neighbor discovery, UDP/TCP DNS, alternative DNS/DoT/UDP, unapproved
  interface rejection, bad signatures, drift repair, expiry, management continuity,
  unrelated-rule preservation, rollback, TLS CA rejection, and signed HTTPS fetch.
- Independent OpenSSL verification of Ed25519 artifact signatures and Chromium's
  CRX3 RSA signature, including corrupted bytes/domain/archive rejection.
- Windows GNU and macOS Intel Rust cross-checks. These do not execute those platforms.

Run `python3 scripts/linux-integration.py` with Docker available. It creates only
named disposable containers and an internal network; it never changes host firewall
rules. `scripts/check-platform-plans.py` invokes native PowerShell/PF parsers in the
CI matrix without activation. Windows/macOS VM acceptance must additionally exercise
IPv4/IPv6 allow/deny, DNS bypass, policy changes on live connections, expiry,
supervisor restart, boot, conflicting management policy, and rollback. That native
acceptance and production certificate verification have not been performed here.

References: [nftables](https://netfilter.org/projects/nftables/manpage.html),
[Windows firewall profiles](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile),
and [Ed25519 strict verification](https://docs.rs/ed25519-dalek/2.2.0/ed25519_dalek/struct.VerifyingKey.html).
