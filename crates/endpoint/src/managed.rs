use crate::{AgentConfig, COMMAND_DOMAIN, ControlPolicy, Envelope, RemoteCommand, runtime};
use anyhow::{Context, ensure};
use std::path::Path;
use wtp_control::{Credential, vault};
fn aad(config: &AgentConfig) -> anyhow::Result<String> {
    Ok(format!(
        "wtp.agent-pool.v1:{}:{}",
        config.endpoint_id,
        config
            .paired_master
            .as_ref()
            .context("Endpoint not paired")?
            .fingerprint()
    ))
}
pub fn enroll(path: &Path, state: &Path, config: &mut AgentConfig) -> anyhow::Result<()> {
    if let Some(bundle) = &config.pairing {
        ensure!(
            bundle.role == "agent" && bundle.endpoint_id.as_deref() == Some(&config.endpoint_id),
            "Use this endpoint's agent invitation"
        );
        let credential = wtp_control::client::pair(bundle, wtp_control::identity::node()?)?;
        ensure!(
            credential.role == "agent"
                && credential.endpoint_id.as_deref() == Some(&config.endpoint_id),
            "Pairing invitation belongs to another endpoint"
        );
        config.paired_master = Some(bundle.master.clone());
        let key = wtp_control::random_hex(32);
        runtime::atomic_write(&state.join("agent-vault.key"), key.as_bytes())?;
        let sealed = vault::seal(
            &wtp_control::key(&key)?,
            &serde_json::to_vec(&vec![credential])?,
            aad(config)?.as_bytes(),
        )?;
        runtime::atomic_write(
            &state.join("agent-vault.json"),
            &serde_json::to_vec(&sealed)?,
        )?;
        config.pairing = None;
        config.token.clear();
        runtime::atomic_write(path, &serde_json::to_vec_pretty(config)?)?;
    }
    if config.paired_master.is_some() {
        credential(state, config)?.validate()?;
    }
    Ok(())
}
pub fn credential(state: &Path, config: &AgentConfig) -> anyhow::Result<Credential> {
    let key = wtp_control::key(std::fs::read_to_string(state.join("agent-vault.key"))?.trim())?;
    let sealed = runtime::read_json(&state.join("agent-vault.json"))?;
    let bytes = vault::open(&key, &sealed, aad(config)?.as_bytes())?;
    let pool: Vec<Credential> = serde_json::from_slice(&bytes)?;
    let credential = pool
        .into_iter()
        .find(|p| {
            p.endpoint_id.as_deref() == Some(&config.endpoint_id)
                && Some(&p.master) == config.paired_master.as_ref()
        })
        .context("Paired identity missing from encrypted credential pool")?;
    credential.validate()?;
    Ok(credential)
}
pub fn fetch(
    config: &AgentConfig,
    state: &Path,
    status: &runtime::Status,
) -> anyhow::Result<ControlPolicy> {
    if config.paired_master.is_some() {
        let credential = credential(state, config)?;
        let response = wtp_control::client::send(
            &credential,
            "POST",
            "/endpoint/policy",
            serde_json::to_string(status)?,
        )?;
        ensure!(response.status == 200, "Paired policy refresh was rejected");
        Ok(serde_json::from_str(&response.body)?)
    } else {
        Ok(ControlPolicy {
            policy: runtime::fetch(config, status)?,
            command: None,
        })
    }
}
fn receipt(credential: &Credential, id: u64, state: &str, detail: &str) -> anyhow::Result<()> {
    let response = wtp_control::client::send(
        credential,
        "POST",
        "/endpoint/command-receipt",
        serde_json::json!({"id":id,"state":state,"detail":detail}).to_string(),
    )?;
    ensure!(response.status == 200, "Command receipt rejected");
    Ok(())
}
pub fn handle_command(
    path: &Path,
    state: &Path,
    config: &AgentConfig,
    envelope: &Envelope,
) -> anyhow::Result<bool> {
    let credential = credential(state, config)?;
    let command: RemoteCommand = crate::verify(
        envelope,
        COMMAND_DOMAIN,
        &crate::public_key(&config.public_key)?,
    )?;
    let watermark = state.join("command-watermark.json");
    let last = if watermark.exists() {
        runtime::read_json::<u64>(&watermark)?
    } else {
        0
    };
    if command.id <= last {
        return Ok(false);
    }
    if let Err(error) = command.validate(config, &credential, last, crate::now()) {
        let _ = receipt(&credential, command.id, "failed", &error.to_string());
        return Ok(false);
    }
    // The server never supplies executable names, file paths, or shell fragments.
    if let Err(error) = crate::uninstall::validate_layout(path, state) {
        let _ = receipt(&credential, command.id, "failed", &error.to_string());
        return Ok(false);
    }
    runtime::atomic_write(&watermark, &serde_json::to_vec(&command.id)?)?;
    receipt(
        &credential,
        command.id,
        "accepted",
        "Authenticated uninstall accepted by the enrolled agent",
    )?;
    match crate::uninstall::remove(path, state) {
        Ok(()) => {
            let _ = receipt(
                &credential,
                command.id,
                "completed",
                "Firewall rolled back, startup disabled, managed credentials and files removed; Windows executable deletion may require reboot",
            );
            crate::uninstall::stop_supervisor();
            Ok(true)
        }
        Err(error) => {
            let _ = receipt(
                &credential,
                command.id,
                "failed",
                &error.to_string().chars().take(400).collect::<String>(),
            );
            Err(error)
        }
    }
}
