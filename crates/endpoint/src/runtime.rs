use crate::{AgentConfig, Envelope, POLICY_DOMAIN, Policy, Watermark, platform};
use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub fn command(exe: &Path, args: &[&str], input: Option<&[u8]>) -> anyhow::Result<String> {
    let mut child = Command::new(exe)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("all_proxy")
        .spawn()
        .with_context(|| format!("Launch {}", exe.display()))?;
    let stdout = child.stdout.take().context("stdout unavailable")?;
    let stderr = child.stderr.take().context("stderr unavailable")?;
    let read = |pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.take(4 * 1024 * 1024)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        })
    };
    let out = read(Box::new(stdout));
    let err = read(Box::new(stderr));
    if let Some(input) = input {
        child
            .stdin
            .take()
            .context("stdin unavailable")?
            .write_all(input)?;
    } else {
        drop(child.stdin.take());
    }
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() > Duration::from_secs(45) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("Platform command timed out");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let stdout = out
        .join()
        .map_err(|_| anyhow::anyhow!("stdout reader failed"))??;
    let stderr = err
        .join()
        .map_err(|_| anyhow::anyhow!("stderr reader failed"))??;
    ensure!(
        status.success(),
        "{} failed: {}",
        exe.display(),
        String::from_utf8_lossy(&stderr)
            .chars()
            .take(512)
            .collect::<String>()
    );
    Ok(String::from_utf8(stdout)?)
}
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let file = std::fs::File::open(path)?;
    ensure!(
        file.metadata()?.len() <= crate::MAX_ENVELOPE,
        "Input exceeds size limit"
    );
    Ok(serde_json::from_reader(file.take(crate::MAX_ENVELOPE + 1))?)
}
pub fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .context("Output must have a parent directory")?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let temp = parent.join(format!(".wtp-{:016x}.tmp", rand::random::<u64>()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok::<_, anyhow::Error>(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}
pub fn require_administrator() -> anyhow::Result<()> {
    #[cfg(unix)]
    ensure!(
        command(Path::new("/usr/bin/id"), &["-u"], None)?.trim() == "0",
        "Activation requires root; use plan for an unprivileged review"
    );
    #[cfg(windows)]
    {
        command(
            &platform::executable("powershell")?,
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {exit 1}",
            ],
            None,
        )?;
    }
    Ok(())
}
pub fn protected(path: &Path) -> anyhow::Result<()> {
    ensure!(path.is_absolute(), "Managed paths must be absolute");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for item in path.ancestors() {
            let meta = std::fs::symlink_metadata(item)?;
            ensure!(
                !meta.file_type().is_symlink() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
                "{} must be root-owned, not a symlink, and not writable by group/others",
                item.display()
            );
        }
    }
    #[cfg(windows)]
    {
        let quoted = path.to_str().context("Invalid path")?.replace('\'', "''");
        let script = format!(
            "$ErrorActionPreference='Stop';$p=Get-Item -LiteralPath '{quoted}';if($p.Attributes -band [IO.FileAttributes]::ReparsePoint){{throw 'Reparse point rejected'}};$acl=Get-Acl -LiteralPath $p.FullName;foreach($a in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){{if($a.AccessControlType -eq 'Allow' -and ($a.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) -and $a.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){{throw 'Managed path has untrusted write access'}}}}"
        );
        command(
            &platform::executable("powershell")?,
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            None,
        )?;
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub state: String,
    pub revision: u64,
    pub checked_at: i64,
    pub detail: String,
    pub fingerprint: String,
}
fn status(state: &Path, value: &Status) -> anyhow::Result<()> {
    atomic_write(&state.join("status.json"), &serde_json::to_vec(value)?)
}
fn quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    )
}
pub fn fetch(config: &AgentConfig, status: &Status) -> anyhow::Result<Envelope> {
    let origin = url::Url::parse(&config.portal)?;
    let host = origin
        .host_str()
        .context("Missing portal host")?
        .trim_matches(['[', ']']);
    let ip = if config.control.is_ipv6() {
        format!("[{}]", config.control.ip())
    } else {
        config.control.ip().to_string()
    };
    let data = serde_json::to_string(status)?;
    let curl = format!(
        "url = {}\nheader = {}\nheader = \"X-WTP-Request: 1\"\nheader = \"Content-Type: application/json\"\nresolve = {}\ndata = {}\n",
        quote(&format!(
            "{}/endpoint/policy",
            config.portal.trim_end_matches('/')
        )),
        quote(&format!("Authorization: Bearer {}", config.token)),
        quote(&format!("{host}:{}:{ip}", config.control.port())),
        quote(&data)
    );
    #[cfg(windows)]
    let executable = PathBuf::from(std::env::var_os("SystemRoot").context("SystemRoot missing")?)
        .join("System32/curl.exe");
    #[cfg(not(windows))]
    let executable = PathBuf::from("/usr/bin/curl");
    let output = command(
        &executable,
        &[
            "-q",
            "--fail",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--max-time",
            "10",
            "--connect-timeout",
            "5",
            "--max-filesize",
            "262144",
            "--config",
            "-",
        ],
        Some(curl.as_bytes()),
    )?;
    ensure!(
        output.len() <= crate::MAX_ENVELOPE as usize,
        "Portal response exceeds limit"
    );
    Ok(serde_json::from_str(&output)?)
}
fn verified(
    envelope: &Envelope,
    config: &AgentConfig,
    watermark: &Watermark,
) -> anyhow::Result<(Policy, Watermark)> {
    let policy = crate::verify::<Policy>(
        envelope,
        POLICY_DOMAIN,
        &crate::public_key(&config.public_key)?,
    )?;
    let next = watermark.accept(&policy, config, crate::now())?;
    Ok((policy, next))
}
pub fn activate(config_path: &Path, state: &Path, envelope: &Envelope) -> anyhow::Result<Status> {
    require_administrator()?;
    protected(config_path)?;
    protected(state)?;
    let _lock = lock(state)?;
    let config: AgentConfig = read_json(config_path)?;
    config.validate()?;
    ensure!(
        config.platform == std::env::consts::OS,
        "Platform does not match this endpoint"
    );
    let watermark = load_watermark(state)?;
    let (policy, next) = verified(envelope, &config, &watermark)?;
    // Persist the anti-rollback watermark before changing kernel state.
    atomic_write(&state.join("watermark.json"), &serde_json::to_vec(&next)?)?;
    atomic_write(&state.join("policy.json"), &serde_json::to_vec(envelope)?)?;
    match platform::apply(&policy.network, state, &config.platform) {
        Ok(fingerprint) => {
            let result = Status {
                state: "enforced".into(),
                revision: policy.revision,
                checked_at: crate::now(),
                detail: "Signed policy applied".into(),
                fingerprint,
            };
            status(state, &result)?;
            Ok(result)
        }
        Err(error) => {
            let fingerprint = platform::apply(&config.quarantine(), state, &config.platform)
                .context("Policy application failed and quarantine could not be established")?;
            let result = Status {
                state: "quarantine".into(),
                revision: policy.revision,
                checked_at: crate::now(),
                detail: "Policy application failed; management-only egress".into(),
                fingerprint,
            };
            status(state, &result)?;
            Err(error)
        }
    }
}
fn load_watermark(state: &Path) -> anyhow::Result<Watermark> {
    let path = state.join("watermark.json");
    if path.exists() {
        read_json(&path)
    } else {
        Ok(Watermark::default())
    }
}
pub fn run(config_path: &Path, state: &Path) -> anyhow::Result<()> {
    require_administrator()?;
    protected(config_path)?;
    protected(state)?;
    let _lock = lock(state)?;
    let config: AgentConfig = read_json(config_path)?;
    config.validate()?;
    ensure!(
        config.platform == std::env::consts::OS,
        "Platform does not match this endpoint"
    );
    let mut watermark = match load_watermark(state) {
        Ok(saved) => saved,
        Err(error) => {
            platform::apply(&config.quarantine(), state, &config.platform)?;
            return Err(error).context("Corrupt anti-rollback state; quarantine established. Administrator recovery required");
        }
    };
    let cached: Option<Envelope> = read_json(&state.join("policy.json")).ok();
    let mut policy = cached
        .as_ref()
        .and_then(|e| verified(e, &config, &watermark).ok())
        .map(|(p, w)| {
            watermark = w;
            p
        });
    let bootstrap = policy
        .as_ref()
        .map(|p| p.network.clone())
        .unwrap_or_else(|| config.quarantine());
    let mut current = Status {
        state: if policy.is_some() {
            "enforced"
        } else {
            "quarantine"
        }
        .into(),
        revision: watermark.revision,
        checked_at: crate::now(),
        detail: "Startup enforcement".into(),
        fingerprint: platform::apply(&bootstrap, state, &config.platform)?,
    };
    status(state, &current)?;
    let mut next_poll = Instant::now();
    loop {
        let now = crate::now();
        let expired =
            policy.as_ref().is_some_and(|p| p.expires_at <= now) || now + 30 < watermark.last_time;
        if expired {
            policy = None;
            current.fingerprint = platform::apply(&config.quarantine(), state, &config.platform)?;
            current.state = "quarantine".into();
            current.detail = "Policy expired or clock rollback; management-only egress".into();
        }
        let desired = policy
            .as_ref()
            .map(|p| &p.network)
            .cloned()
            .unwrap_or_else(|| config.quarantine());
        if platform::fingerprint(state, &config.platform).as_ref().ok()
            != Some(&current.fingerprint)
        {
            current.fingerprint = platform::apply(&desired, state, &config.platform)?;
            current.detail = "Firewall drift detected and repaired".into();
        }
        if Instant::now() >= next_poll {
            match fetch(&config, &current).and_then(|e| {
                let (p, w) = verified(&e, &config, &watermark)?;
                Ok((e, p, w))
            }) {
                Ok((envelope, p, next)) => {
                    let changed = policy.as_ref().is_none_or(|old| old.network != p.network);
                    atomic_write(&state.join("watermark.json"), &serde_json::to_vec(&next)?)?;
                    atomic_write(&state.join("policy.json"), &serde_json::to_vec(&envelope)?)?;
                    if changed {
                        match platform::apply(&p.network, state, &config.platform) {
                            Ok(fingerprint) => current.fingerprint = fingerprint,
                            Err(error) => {
                                current.fingerprint =
                                    platform::apply(&config.quarantine(), state, &config.platform)?;
                                current.state = "quarantine".into();
                                current.detail = format!("Policy application failed: {error}")
                                    .chars()
                                    .take(256)
                                    .collect();
                                status(state, &current)?;
                                return Err(error);
                            }
                        }
                    }
                    watermark = next;
                    current.revision = p.revision;
                    policy = Some(p);
                    current.state = "enforced".into();
                    current.detail = "Signed policy current".into();
                }
                Err(_) => {
                    current.detail =
                        "Policy refresh failed; last verified policy retained until expiry".into();
                }
            }
            next_poll = Instant::now() + Duration::from_secs(30);
        }
        current.checked_at = crate::now();
        status(state, &current)?;
        std::thread::sleep(Duration::from_secs(2));
    }
}

pub fn lock(state: &Path) -> anyhow::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(state.join("agent.lock"))?;
    file.try_lock()
        .context("Another agent owns this state directory; stop it before apply or rollback")?;
    Ok(file)
}
