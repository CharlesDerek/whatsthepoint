use anyhow::{Context, ensure};
use std::process::Command;
fn output(path: &str, args: &[&str]) -> anyhow::Result<String> {
    let result = Command::new(path).args(args).output()?;
    ensure!(result.status.success(), "OS identity query failed");
    Ok(String::from_utf8(result.stdout)?.trim().to_owned())
}
pub fn mac_addresses() -> anyhow::Result<Vec<String>> {
    let mut macs = Vec::new();
    #[cfg(target_os = "linux")]
    for entry in std::fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        if entry.path().join("device").exists()
            && let Ok(value) = std::fs::read_to_string(entry.path().join("address"))
        {
            macs.push(value.trim().to_lowercase());
        }
    }
    #[cfg(target_os = "macos")]
    {
        let text = output("/sbin/ifconfig", &["-a"])?;
        for line in text.lines() {
            if let Some(value) = line.trim().strip_prefix("ether ") {
                macs.push(value.trim().to_lowercase());
            }
        }
    }
    #[cfg(windows)]
    {
        let root = std::env::var("SystemRoot").context("SystemRoot missing")?;
        let text = output(
            &format!("{root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetAdapter -Physical | Select-Object -ExpandProperty MacAddress",
            ],
        )?;
        macs.extend(
            text.lines()
                .map(|s| s.trim().replace('-', ":").to_lowercase()),
        );
    }
    macs.retain(|s| s != "00:00:00:00:00:00");
    macs.sort();
    macs.dedup();
    macs.truncate(32);
    crate::validate_macs(&macs)?;
    Ok(macs)
}
pub fn node() -> anyhow::Result<crate::Node> {
    #[cfg(unix)]
    let account_id = output("/usr/bin/id", &["-u"])?;
    #[cfg(windows)]
    let account_id = {
        let root = std::env::var("SystemRoot").context("SystemRoot missing")?;
        let text = output(
            &format!("{root}\\System32\\whoami.exe"),
            &["/user", "/fo", "csv", "/nh"],
        )?;
        text.trim_matches('"')
            .split_once("\",\"")
            .context("Invalid account SID output")?
            .1
            .to_owned()
    };
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "desktop".into());
    let node = crate::Node {
        installation_id: crate::random_hex(16),
        platform: std::env::consts::OS.into(),
        account_id,
        hostname: hostname.chars().take(256).collect(),
        mac_addresses: mac_addresses().context("Read network adapter identities")?,
    };
    node.validate()?;
    Ok(node)
}
