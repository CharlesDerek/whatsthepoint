# Running the filter

## Before switching DNS

Build and initialize the resolver using the README. Install a community feed in the console and test an allowed domain and `blocked.test` over both UDP and TCP. Save the current device/router DNS settings before changing them.

Normal OS DNS settings expect port **53**. Port 5354 is for development tests only. Do not configure an unfiltered public resolver as the device's secondary DNS: clients may use it at any time, bypassing WTP. For availability, run a second WTP instance with the same policy and configure both addresses.

The daemon never changes system networking automatically. Use the examples below only on the interface you intend to filter. Flush browser/OS DNS caches after changing policy if testing an already-visited site.

## Linux

For a foreground port-53 deployment, grant only bind capability to the built binary:

```sh
sudo install -m 0755 target/release/wtp /usr/local/bin/wtp
sudo setcap cap_net_bind_service=+ep /usr/local/bin/wtp
/usr/local/bin/wtp config > wtp.toml
# Edit dns_bind to "127.0.0.1:53".
/usr/local/bin/wtp --config wtp.toml --data-dir data serve
```

For a persistent service, [deploy/linux/wtp.service](../deploy/linux/wtp.service) uses a dedicated user, a restricted filesystem, and the single required capability:

```sh
sudo useradd --system --home-dir /var/lib/wtp --shell /usr/sbin/nologin wtp
sudo install -d -o wtp -g wtp -m 0700 /var/lib/wtp
sudo install -d -m 0755 /etc/wtp
sudo install -m 0755 target/release/wtp /usr/local/bin/wtp
sudo install -m 0644 deploy/wtp.example.toml /etc/wtp/wtp.toml
sudo -u wtp /usr/local/bin/wtp --data-dir /var/lib/wtp init
sudo install -m 0644 deploy/linux/wtp.service /etc/systemd/system/wtp.service
sudo systemctl daemon-reload
sudo systemctl enable --now wtp
sudo journalctl -u wtp -f
```

The sample config listens on loopback port 53. Check `ss -luntp` if it is already occupied. Many systems use `systemd-resolved` on 127.0.0.53; binding WTP specifically to 127.0.0.1 can coexist with that. Do not disable your existing resolver until WTP answers correctly.

For NetworkManager, inspect the active profile with `nmcli connection show --active`. Save its existing values, then set DNS on that profile:

```sh
# Replace YOUR_CONNECTION with the actual profile name.
nmcli connection modify "YOUR_CONNECTION" ipv4.dns "127.0.0.1" ipv4.ignore-auto-dns yes
nmcli connection modify "YOUR_CONNECTION" ipv6.ignore-auto-dns yes
nmcli connection up "YOUR_CONNECTION"
```

IPv4 DNS can resolve both A and AAAA records. Ensure another IPv6 DNS server is not still configured. Systems using another network manager should configure DNS through that manager instead.

**Rollback:** restore the saved IPv4/IPv6 DNS and auto-DNS values, reactivate the connection, and then stop/disable WTP. If the previous configuration used DHCP DNS exclusively, reset `ipv4.dns`/`ipv6.dns` to empty and both `ignore-auto-dns` values to `no`.

## macOS

The binary runs natively on Apple Silicon and Intel. For foreground development, use port 5354 without elevated privileges. The supplied launchd template binds port 53 as root. Its binary, configuration, and data must therefore be writable only by administrators.

```sh
sudo install -m 0755 target/release/wtp /usr/local/bin/wtp
sudo mkdir -p "/Library/Application Support/WhatsThePoint"
sudo chmod 700 "/Library/Application Support/WhatsThePoint"
sudo cp deploy/wtp.example.toml "/Library/Application Support/WhatsThePoint/wtp.toml"
sudo /usr/local/bin/wtp --data-dir "/Library/Application Support/WhatsThePoint/data" init
sudo cp deploy/macos/com.whatsthepoint.filter.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/com.whatsthepoint.filter.plist
sudo chmod 644 /Library/LaunchDaemons/com.whatsthepoint.filter.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.whatsthepoint.filter.plist
```

Inspect `/var/log/whatsthepoint.log` and `/var/log/whatsthepoint-error.log`. First verify `dig @127.0.0.1 blocked.test`. List network service names with `networksetup -listallnetworkservices`, then:

```sh
networksetup -getdnsservers "Wi-Fi"         # Save this output for rollback.
sudo networksetup -setdnsservers "Wi-Fi" 127.0.0.1
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```

**Rollback:** restore the saved DNS addresses, or use `networksetup -setdnsservers "Wi-Fi" Empty` if the service originally used automatic DNS. Then unload the daemon using `sudo launchctl bootout system /Library/LaunchDaemons/com.whatsthepoint.filter.plist`.

## Windows

Build with the MSVC Rust toolchain and Visual Studio C++ build tools, or download the Windows executable from a successful CI run. Start with `wtp.exe init` and `wtp.exe serve`.

For a machine-start installation, the provided script registers a **Task Scheduler task**. This is not a native Windows Service Control Manager service; do not use `sc.exe create` with the executable.

In an elevated PowerShell terminal:

```powershell
New-Item -ItemType Directory -Force 'C:\Program Files\WhatsThePoint'
New-Item -ItemType Directory -Force 'C:\ProgramData\WhatsThePoint'
Copy-Item .\target\release\wtp.exe 'C:\Program Files\WhatsThePoint\wtp.exe'
Copy-Item .\deploy\wtp.example.toml 'C:\ProgramData\WhatsThePoint\wtp.toml'
& 'C:\Program Files\WhatsThePoint\wtp.exe' --data-dir 'C:\ProgramData\WhatsThePoint\data' init
.\deploy\windows\install-task.ps1
```

The script restricts the data directory to SYSTEM and Administrators and starts the task as SYSTEM. The binary stays under Program Files. It does not change DNS or firewall rules.

After verifying the resolver, save existing DNS settings and configure the intended interface:

```powershell
Get-DnsClientServerAddress
# Replace Wi-Fi with the correct interface alias.
Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ServerAddresses '127.0.0.1'
Clear-DnsClientCache
Resolve-DnsName blocked.test -Server 127.0.0.1
```

**Rollback:** restore your saved addresses, or use `Set-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -ResetServerAddresses` if previously automatic. Then `Stop-ScheduledTask -TaskName 'WhatsThePoint'` and `Unregister-ScheduledTask -TaskName 'WhatsThePoint'`.

A stopped task causes DNS failure until restarted or DNS is restored. Test startup/reboot behavior on the intended machine before relying on it unattended.

## Remote console

The application speaks HTTP. TLS belongs at a reverse proxy, with the backend kept on loopback. Example `wtp.toml`:

```toml
http_bind = "127.0.0.1:8080"
public_origin = "https://filter.example.com"
```

Example Caddy configuration:

```caddyfile
filter.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

The proxy must preserve the original `Host`. HTTPS origins enable Secure session cookies. Do not publish the backend port directly. Strict Host checking also means that the default local console is reached at `127.0.0.1`, not `localhost`, unless you change `public_origin`.

Login throttling uses the actual TCP peer, never untrusted forwarded headers. Behind a reverse proxy its ten-attempt/five-minute limit is shared by clients of that proxy. Add proxy-level rate limits if serving many administrators.

## Backup and recovery

Stop the process before copying the entire data directory, then restart it. This captures SQLite and any WAL sidecars consistently. Do not copy just a live `wtp.db` file while ignoring `wtp.db-wal`. For live backups use SQLite's backup API or `.backup` command.

Recover a password locally:

```sh
wtp --data-dir /path/to/data reset-password --username admin
```

This revokes existing sessions. Automation may supply `WTP_ADMIN_PASSWORD` through an environment secret; do not put passwords in shell arguments or commit them.

## DNS enforcement boundaries

- A browser using its own DoH resolver can bypass system DNS. Managed browsers need enterprise DNS policy.
- A device owner can use a VPN, an alternate resolver, a proxy, or a direct IP.
- Network enforcement needs firewall rules for external DNS/DoT and controls for browser DoH; blocking port 53 alone is insufficient.
- A gateway may hide DNS clients behind its own IP. Browser enrollment and native OS account binding are separate; see [browser protection](browser-protection.md).
- DNS domain filtering cannot distinguish paths. The browser extension adds URL path rules and content categories; it does not rewrite arbitrary interactive sites to remove every ad.
- DNS NXDOMAIN cannot render a block page inside HTTPS connections. The extension uses its own navigation check/block page.
- The resolver does not implement DNS64, split DNS, local authoritative zones, DNSSEC validation of its own, TLS interception, or independent CNAME lookups.

Deploy alongside managed endpoint/network controls when tamper resistance matters. Do not describe this release as tamper-proof.

## Privileged endpoint controls

The DNS service setup above is separate from the device-wide firewall agent. Follow [endpoint enrollment, activation, validation, and rollback](endpoint-enforcement.md) for Linux/systemd, Windows/SYSTEM, and macOS/launchd. Review [release verification and signing](release-signing.md) before installing privileged binaries.
