use anyhow::{Context, ensure};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use wtp_endpoint::{
    AgentConfig, Envelope, FileClaim, POLICY_DOMAIN, Policy, RELEASE_DOMAIN, Watermark, platform,
    runtime,
};
#[derive(Parser)]
#[command(
    name = "wtp-agent",
    version,
    about = "Signed endpoint policy, kernel firewall enforcement and release verification"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Generate a private Ed25519 key file; prints only the public key.
    Keygen {
        #[arg(long)]
        output: PathBuf,
    },
    SignPolicy {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Download and verify a fresh policy over HTTPS, without activating it.
    Fetch {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify policy and print platform rules without activating them.
    Plan {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        policy: PathBuf,
    },
    /// Establish management-only egress before networking starts.
    Bootstrap {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Requires administrator-owned config/state paths; changes this device's firewall.
    Apply {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Privileged supervisor: poll signed policies and repair firewall drift.
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Stop the supervisor before rollback. Anti-rollback history is retained.
    Rollback {
        #[arg(long)]
        state_dir: PathBuf,
    },
    Status {
        #[arg(long)]
        state_dir: PathBuf,
    },
    SignFile {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    VerifyFile {
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        signature: PathBuf,
    },
}
fn key(path: &Path) -> anyhow::Result<ed25519_dalek::SigningKey> {
    wtp_endpoint::private_key(&std::fs::read_to_string(path)?)
}
fn save(path: &Path, value: &impl serde::Serialize) -> anyhow::Result<()> {
    runtime::atomic_write(path, &serde_json::to_vec_pretty(value)?)
}
fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Keygen { output } => {
            ensure!(!output.exists(), "Refusing to overwrite an existing key");
            let key = wtp_endpoint::generate_key();
            runtime::atomic_write(&output, hex::encode(key.to_bytes()).as_bytes())?;
            println!("{}", hex::encode(key.verifying_key().to_bytes()));
        }
        Command::SignPolicy {
            key: private,
            policy,
            output,
        } => {
            let policy: Policy = runtime::read_json(&policy)?;
            policy.validate(&policy.endpoint_id, &policy.platform, wtp_endpoint::now())?;
            save(
                &output,
                &wtp_endpoint::sign(&policy, POLICY_DOMAIN, &key(&private)?)?,
            )?;
        }
        Command::Fetch { config, output } => {
            let config: AgentConfig = runtime::read_json(&config)?;
            config.validate()?;
            let envelope = runtime::fetch(
                &config,
                &runtime::Status {
                    state: "preview".into(),
                    detail: "Unprivileged policy preview; firewall not activated".into(),
                    checked_at: wtp_endpoint::now(),
                    ..Default::default()
                },
            )?;
            let policy: Policy = wtp_endpoint::verify(
                &envelope,
                POLICY_DOMAIN,
                &wtp_endpoint::public_key(&config.public_key)?,
            )?;
            Watermark::default().accept(&policy, &config, wtp_endpoint::now())?;
            save(&output, &envelope)?;
            println!(
                "Verified policy revision {}. Firewall not activated.",
                policy.revision
            );
        }
        Command::Plan { config, policy } => {
            let config: AgentConfig = runtime::read_json(&config)?;
            let envelope: Envelope = runtime::read_json(&policy)?;
            let policy: Policy = wtp_endpoint::verify(
                &envelope,
                POLICY_DOMAIN,
                &wtp_endpoint::public_key(&config.public_key)?,
            )?;
            Watermark::default().accept(&policy, &config, wtp_endpoint::now())?;
            print!("{}", platform::render(&policy.network, &config.platform)?);
        }
        Command::Bootstrap { config, state_dir } => {
            runtime::require_administrator()?;
            runtime::protected(&config)?;
            runtime::protected(&state_dir)?;
            let _lock = runtime::lock(&state_dir)?;
            let config: AgentConfig = runtime::read_json(&config)?;
            config.validate()?;
            platform::apply(&config.quarantine(), &state_dir, &config.platform)?;
        }
        Command::Apply {
            config,
            policy,
            state_dir,
        } => {
            let result = runtime::activate(&config, &state_dir, &runtime::read_json(&policy)?)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Run { config, state_dir } => runtime::run(&config, &state_dir)?,
        Command::Rollback { state_dir } => {
            runtime::require_administrator()?;
            runtime::protected(&state_dir)?;
            let _lock = runtime::lock(&state_dir)?;
            platform::rollback(&state_dir, std::env::consts::OS)?;
            println!("Endpoint firewall removed/restored. Anti-rollback history retained.");
        }
        Command::Status { state_dir } => {
            let mut status: runtime::Status = runtime::read_json(&state_dir.join("status.json"))?;
            status.state = if platform::fingerprint(&state_dir, std::env::consts::OS)
                .ok()
                .as_ref()
                == Some(&status.fingerprint)
            {
                status.state
            } else {
                "drift-or-unavailable".into()
            };
            if wtp_endpoint::now() - status.checked_at > 45 {
                status.state = "supervisor-stale".into();
            }
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        Command::SignFile {
            key: private,
            file,
            output,
        } => save(
            &output,
            &wtp_endpoint::sign(
                &wtp_endpoint::file_claim(&file)?,
                RELEASE_DOMAIN,
                &key(&private)?,
            )?,
        )?,
        Command::VerifyFile {
            public_key,
            file,
            signature,
        } => {
            let envelope: Envelope = runtime::read_json(&signature)?;
            let signed: FileClaim = wtp_endpoint::verify(
                &envelope,
                RELEASE_DOMAIN,
                &wtp_endpoint::public_key(&public_key)?,
            )?;
            let actual = wtp_endpoint::file_claim(&file)?;
            ensure!(
                actual.name == signed.name
                    && actual.bytes == signed.bytes
                    && actual.sha256 == signed.sha256,
                "Artifact does not match its signed claim"
            );
            println!("Verified {} ({} bytes)", actual.name, actual.bytes);
        }
    };
    std::io::Write::flush(&mut std::io::stdout()).context("flush output")?;
    Ok(())
}
