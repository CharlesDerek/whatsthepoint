use crate::NetworkPolicy;
use anyhow::{bail, ensure};
use serde_json::json;
use std::{net::SocketAddr, path::Path};

pub fn render(network: &NetworkPolicy, platform: &str) -> anyhow::Result<String> {
    network.validate()?;
    match platform {
        "linux" => Ok(nft(network)),
        "macos" => Ok(pf(network)),
        "windows" => Ok(windows(network)),
        _ => bail!("Unsupported firewall platform"),
    }
}
fn nft(network: &NetworkPolicy) -> String {
    let interfaces = network
        .interfaces
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let mut out = format!(
        "add table inet wtp_endpoint\nflush table inet wtp_endpoint\ntable inet wtp_endpoint {{\n chain output {{\n  type filter hook output priority 100; policy drop;\n  oifname \"lo\" accept\n  oifname != {{ {interfaces} }} counter drop\n"
    );
    for (protocol, addresses) in [("tcp", network.tcp()), ("udp", network.udp())] {
        for address in addresses {
            out.push_str(&format!(
                "  {} daddr {} {protocol} dport {} counter accept\n",
                if address.is_ipv4() { "ip" } else { "ip6" },
                address.ip(),
                address.port()
            ));
        }
    }
    if network.dhcp {
        out.push_str("  udp sport 68 udp dport 67 counter accept\n  ip6 daddr ff02::1:2 udp sport 546 udp dport 547 counter accept\n");
    }
    out.push_str("  ip6 hoplimit 255 icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept\n  counter drop\n }\n}\n");
    out
}
fn pf(network: &NetworkPolicy) -> String {
    let interfaces = network
        .interfaces
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let mut out = String::from(
        "# WTP owns this anchor. Its parent must be the first quick filter anchor.\npass quick on lo0 all no state\n",
    );
    for (protocol, addresses) in [("tcp", network.tcp()), ("udp", network.udp())] {
        for address in addresses {
            out.push_str(&format!("pass out quick on {{ {interfaces} }} {} proto {protocol} from any to {} port {} keep state\n",if address.is_ipv4(){"inet"}else{"inet6"},address.ip(),address.port()));
        }
    }
    if network.dhcp {
        out.push_str(&format!("pass out quick on {{ {interfaces} }} inet proto udp from any port 68 to any port 67 keep state\npass out quick on {{ {interfaces} }} inet6 proto udp from any port 546 to ff02::1:2 port 547 keep state\npass in quick on {{ {interfaces} }} inet proto udp from any port 67 to any port 68 no state\npass in quick on {{ {interfaces} }} inet6 proto udp from fe80::/10 port 547 to any port 546 no state\n"));
    }
    out.push_str(&format!("pass quick on {{ {interfaces} }} inet6 proto icmp6 from any to any icmp6-type {{ routersol, routeradv, neighbrsol, neighbradv }} no state\nblock drop quick all\n"));
    out
}
fn windows(network: &NetworkPolicy) -> String {
    let endpoints = |addresses: std::collections::BTreeSet<SocketAddr>| {
        addresses
            .iter()
            .map(|a| json!({"address":a.ip().to_string(),"port":a.port()}))
            .collect::<Vec<_>>()
    };
    let json=json!({"interfaces":network.interfaces,"tcp":endpoints(network.tcp()),"udp":endpoints(network.udp()),"dhcp":network.dhcp}).to_string().replace('\'',"''");
    format!(
        "param([string]$Mode = 'Apply', [Parameter(Mandatory=$true)][string]$StateDir)\n$Policy = ConvertFrom-Json '{json}'\n{}",
        include_str!("../../../deploy/endpoint/windows-firewall.ps1")
    )
}

pub fn executable(name: &str) -> anyhow::Result<std::path::PathBuf> {
    let path = match name {
        "nft" => ["/usr/sbin/nft", "/sbin/nft"]
            .iter()
            .map(std::path::PathBuf::from)
            .find(|p| p.exists())
            .ok_or_else(|| anyhow::anyhow!("Install nftables first"))?,
        "pfctl" => "/sbin/pfctl".into(),
        "powershell" => std::path::PathBuf::from(
            std::env::var_os("SystemRoot").ok_or_else(|| anyhow::anyhow!("SystemRoot missing"))?,
        )
        .join("System32/WindowsPowerShell/v1.0/powershell.exe"),
        _ => bail!("Unknown platform tool"),
    };
    ensure!(path.is_absolute(), "Platform tool must be absolute");
    Ok(path)
}
fn command(name: &str, args: &[&str], input: Option<&[u8]>) -> anyhow::Result<String> {
    crate::runtime::command(&executable(name)?, args, input)
}
fn path_str(path: &Path) -> anyhow::Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("Non-UTF8 state path"))
}

pub fn apply(network: &NetworkPolicy, state: &Path, platform: &str) -> anyhow::Result<String> {
    ensure!(
        platform == std::env::consts::OS,
        "Cannot activate a foreign platform policy"
    );
    let rules = render(network, platform)?;
    match platform {
        "linux" => {
            command("nft", &["--check", "-f", "-"], Some(rules.as_bytes()))?;
            command("nft", &["-f", "-"], Some(rules.as_bytes()))?;
        }
        "macos" => {
            let parent = command("pfctl", &["-sr"], None)?;
            ensure!(
                parent
                    .lines()
                    .find(|line| line.starts_with("anchor ")
                        || line.starts_with("pass ")
                        || line.starts_with("block "))
                    .is_some_and(|line| line.starts_with("anchor \"org.whatsthepoint\"")
                        && line.contains("quick")),
                "Install the WTP first quick PF anchor before activation"
            );
            let enabled = command("pfctl", &["-s", "info"], None)?;
            ensure!(
                enabled.contains("Status: Enabled"),
                "PF must be enabled by the endpoint installer"
            );
            command(
                "pfctl",
                &["-a", "org.whatsthepoint", "-nf", "-"],
                Some(rules.as_bytes()),
            )?;
            command(
                "pfctl",
                &["-a", "org.whatsthepoint", "-f", "-"],
                Some(rules.as_bytes()),
            )?;
            // Previously created PF states bypass new filter rules. Installation
            // and each policy change deliberately invalidate them.
            command("pfctl", &["-F", "states"], None)?;
        }
        "windows" => {
            let path = state.join("firewall.ps1");
            crate::runtime::atomic_write(&path, rules.as_bytes())?;
            command(
                "powershell",
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    path_str(&path)?,
                    "-Mode",
                    "Apply",
                    "-StateDir",
                    path_str(state)?,
                ],
                None,
            )?;
        }
        _ => bail!("Unsupported firewall platform"),
    }
    fingerprint(state, platform)
}
pub fn fingerprint(state: &Path, platform: &str) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let output = match platform {
        "linux" => command(
            "nft",
            &["-s", "list", "table", "inet", "wtp_endpoint"],
            None,
        )?,
        "macos" => format!(
            "{}{}{}",
            command("pfctl", &["-s", "info"], None)?.contains("Status: Enabled"),
            command("pfctl", &["-sr"], None)?,
            command("pfctl", &["-a", "org.whatsthepoint", "-sr"], None)?
        ),
        "windows" => command(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                path_str(&state.join("firewall.ps1"))?,
                "-Mode",
                "Check",
                "-StateDir",
                path_str(state)?,
            ],
            None,
        )?,
        _ => bail!("Unsupported platform"),
    };
    Ok(hex::encode(Sha256::digest(output.as_bytes())))
}
pub fn rollback(state: &Path, platform: &str) -> anyhow::Result<()> {
    ensure!(
        platform == std::env::consts::OS,
        "Cannot roll back a foreign platform"
    );
    match platform {
        "linux" => {
            command("nft", &["delete", "table", "inet", "wtp_endpoint"], None)?;
        }
        "macos" => {
            command("pfctl", &["-a", "org.whatsthepoint", "-F", "rules"], None)?;
            command("pfctl", &["-F", "states"], None)?;
        }
        "windows" => {
            command(
                "powershell",
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    path_str(&state.join("firewall.ps1"))?,
                    "-Mode",
                    "Rollback",
                    "-StateDir",
                    path_str(state)?,
                ],
                None,
            )?;
        }
        _ => bail!("Unsupported platform"),
    };
    Ok(())
}
