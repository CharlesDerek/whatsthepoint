//! Remote removal is a fixed local operation, constrained to the installed WTP paths.
use crate::{platform, runtime};
#[cfg(windows)]
use anyhow::Context;
use anyhow::ensure;
use std::path::{Path, PathBuf};
fn layout() -> anyhow::Result<(PathBuf, PathBuf, PathBuf)> {
    #[cfg(target_os = "linux")]
    return Ok((
        "/etc/wtp-endpoint/config.json".into(),
        "/var/lib/wtp-endpoint".into(),
        "/usr/local/libexec/wtp/wtp-agent".into(),
    ));
    #[cfg(target_os = "macos")]
    return Ok((
        "/Library/Application Support/WhatsThePoint/Endpoint/config.json".into(),
        "/Library/Application Support/WhatsThePoint/Endpoint".into(),
        "/usr/local/libexec/wtp/wtp-agent".into(),
    ));
    #[cfg(windows)]
    {
        let data = PathBuf::from(std::env::var_os("ProgramData").context("ProgramData missing")?)
            .join("WhatsThePoint/Endpoint");
        let exe = PathBuf::from(std::env::var_os("ProgramFiles").context("ProgramFiles missing")?)
            .join("WhatsThePoint/wtp-agent.exe");
        Ok((data.join("config.json"), data, exe))
    }
}
pub fn validate_layout(config: &Path, state: &Path) -> anyhow::Result<()> {
    runtime::require_administrator()?;
    runtime::protected(config)?;
    runtime::protected(state)?;
    let (expected_config, expected_state, expected_binary) = layout()?;
    ensure!(
        config == expected_config && state == expected_state,
        "Remote uninstall requires the standard protected installation layout"
    );
    ensure!(
        std::env::current_exe()?.canonicalize()? == expected_binary.canonicalize()?,
        "Remote uninstall only removes the standard installed executable"
    );
    Ok(())
}
fn remove_file(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
#[cfg(windows)]
fn powershell(script: &str) -> anyhow::Result<()> {
    runtime::command(
        &platform::executable("powershell")?,
        &["-NoProfile", "-NonInteractive", "-Command", script],
        None,
    )?;
    Ok(())
}
pub fn remove(config: &Path, state: &Path) -> anyhow::Result<()> {
    validate_layout(config, state)?;
    let (_, _, binary) = layout()?;
    #[cfg(target_os = "linux")]
    if Path::new("/etc/systemd/system/wtp-endpoint.service").exists() {
        runtime::command(
            Path::new("/usr/bin/systemctl"),
            &["disable", "wtp-endpoint.service"],
            None,
        )?;
    }
    #[cfg(target_os = "macos")]
    {
        runtime::command(
            Path::new("/bin/launchctl"),
            &["disable", "system/org.whatsthepoint.endpoint"],
            None,
        )?;
    }
    #[cfg(windows)]
    powershell(
        "$ErrorActionPreference='Stop';Disable-ScheduledTask -TaskName 'WhatsThePointEndpoint' | Out-Null;Unregister-ScheduledTask -TaskName 'WhatsThePointEndpoint' -Confirm:$false",
    )?;
    platform::rollback(state, std::env::consts::OS)?;
    #[cfg(target_os = "macos")]
    {
        let conf = Path::new("/etc/pf.conf");
        let original = std::fs::read_to_string(conf)?;
        let cleaned=original.lines().filter(|line|!matches!(line.trim(),"anchor \"org.whatsthepoint\" quick"|"load anchor \"org.whatsthepoint\" from \"/etc/pf.anchors/org.whatsthepoint\"")).collect::<Vec<_>>().join("\n")+"\n";
        runtime::command(
            Path::new("/sbin/pfctl"),
            &["-nf", "-"],
            Some(cleaned.as_bytes()),
        )?;
        // /etc is a platform symlink; atomic replacement uses its canonical directory.
        runtime::atomic_write(&conf.canonicalize()?, cleaned.as_bytes())?;
        runtime::command(Path::new("/sbin/pfctl"), &["-f", "/etc/pf.conf"], None)?;
        remove_file(Path::new("/etc/pf.anchors/org.whatsthepoint"))?;
        remove_file(Path::new(
            "/Library/LaunchDaemons/org.whatsthepoint.endpoint.plist",
        ))?;
    }
    #[cfg(target_os = "linux")]
    remove_file(Path::new("/etc/systemd/system/wtp-endpoint.service"))?;
    // Remove only names this agent owns, never recursively remove a supplied directory.
    for name in [
        "agent-vault.key",
        "agent-vault.json",
        "policy.json",
        "watermark.json",
        "command-watermark.json",
        "status.json",
        "firewall.ps1",
    ] {
        remove_file(&state.join(name))?;
    }
    remove_file(config)?;
    #[cfg(unix)]
    remove_file(&binary)?;
    #[cfg(windows)]
    {
        let path = binary
            .to_str()
            .context("Invalid executable path")?
            .replace('\'', "''");
        let script = format!(
            "$ErrorActionPreference='Stop';Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class WtpDelete {{[DllImport(\"kernel32.dll\",CharSet=CharSet.Unicode,SetLastError=true)]public static extern bool MoveFileEx(string oldName,string newName,int flags);}}';if(-not [WtpDelete]::MoveFileEx('{path}',$null,4)){{throw 'Could not schedule executable removal'}}"
        );
        powershell(&script)?;
    }
    Ok(())
}
pub fn stop_supervisor() {
    #[cfg(target_os = "linux")]
    {
        let _ = runtime::command(Path::new("/usr/bin/systemctl"), &["daemon-reload"], None);
        let _ = runtime::command(
            Path::new("/usr/bin/systemctl"),
            &["stop", "--no-block", "wtp-endpoint.service"],
            None,
        );
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("/bin/launchctl")
            .args(["bootout", "system/org.whatsthepoint.endpoint"])
            .spawn();
    }
}
