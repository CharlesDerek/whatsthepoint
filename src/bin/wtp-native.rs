//! Minimal, read-only native messaging host. It exposes the launching OS account,
//! never executes commands supplied by a page, and never receives browser secrets.
use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    process::Command,
};
use whatsthepoint::browser::Identity;

fn output(command: &mut Command) -> anyhow::Result<String> {
    let result = command.output().context("query OS account")?;
    ensure!(result.status.success(), "OS account query failed");
    Ok(String::from_utf8(result.stdout)?.trim().to_owned())
}
fn identity() -> anyhow::Result<Identity> {
    #[cfg(unix)]
    {
        Ok(Identity {
            os: std::env::consts::OS.into(),
            account_id: output(Command::new("/usr/bin/id").arg("-u"))?,
            username: output(Command::new("/usr/bin/id").arg("-un"))?,
        })
    }
    #[cfg(windows)]
    {
        // Use the Windows account SID, not USERNAME or another writable environment claim.
        let root = std::env::var_os("SystemRoot").context("SystemRoot is missing")?;
        let text = output(
            Command::new(std::path::PathBuf::from(root).join("System32/whoami.exe"))
                .args(["/user", "/fo", "csv", "/nh"]),
        )?;
        let (username, account_id) = text
            .trim_matches('"')
            .split_once("\",\"")
            .context("unexpected whoami output")?;
        ensure!(account_id.starts_with("S-1-"), "invalid account SID");
        Ok(Identity {
            os: "windows".into(),
            account_id: account_id.into(),
            username: username.into(),
        })
    }
}
fn serve(mut input: impl Read, mut out: impl Write) -> anyhow::Result<()> {
    loop {
        let mut length = [0; 4];
        // Distinguish a clean end-of-stream from a truncated frame.
        if input.read(&mut length[..1])? == 0 {
            return Ok(());
        }
        input.read_exact(&mut length[1..])?;
        let length = u32::from_ne_bytes(length) as usize;
        ensure!(
            length > 0 && length <= 65536,
            "invalid native message length"
        );
        let mut bytes = vec![0; length];
        input.read_exact(&mut bytes)?;
        let request: Value = serde_json::from_slice(&bytes)?;
        let response = if request == json!({"type":"identity"}) {
            match identity() {
                Ok(identity) => json!({"identity":identity}),
                Err(_) => json!({"error":"OS identity is unavailable"}),
            }
        } else {
            json!({"error":"Only the identity operation is supported"})
        };
        let bytes = serde_json::to_vec(&response)?;
        out.write_all(&(bytes.len() as u32).to_ne_bytes())?;
        out.write_all(&bytes)?;
        out.flush()?;
    }
}
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--identity") {
        println!("{}", serde_json::to_string_pretty(&identity()?)?);
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("--manifest") {
        let id = args
            .get(1)
            .context("usage: wtp-native --manifest EXTENSION_ID")?;
        ensure!(
            id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b)),
            "invalid extension ID"
        );
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"name":"org.whatsthepoint.identity","description":"What's the Point desktop identity","path":std::env::current_exe()?,"type":"stdio","allowed_origins":[format!("chrome-extension://{id}/")]})
            )?
        );
        return Ok(());
    }
    if args
        .first()
        .is_some_and(|a| !a.starts_with("chrome-extension://"))
    {
        bail!("Use --identity, --manifest EXTENSION_ID, or launch through the browser");
    }
    serve(std::io::stdin().lock(), std::io::stdout().lock())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framed_protocol_rejects_commands_and_truncation() {
        let bytes = br#"{"type":"execute","command":"echo unsafe"}"#;
        let mut frame = (bytes.len() as u32).to_ne_bytes().to_vec();
        frame.extend(bytes);
        let mut out = vec![];
        serve(&frame[..], &mut out).unwrap();
        let length = u32::from_ne_bytes(out[..4].try_into().unwrap()) as usize;
        assert_eq!(length, out.len() - 4);
        assert!(serde_json::from_slice::<Value>(&out[4..]).unwrap()["error"].is_string());
        assert!(serve(&[1, 0][..], Vec::new()).is_err());
        assert!(serve(&u32::MAX.to_ne_bytes()[..], Vec::new()).is_err());
    }
    #[test]
    fn reads_actual_os_account() {
        let identity = identity().unwrap();
        assert!(!identity.account_id.is_empty());
        assert!(!identity.username.is_empty());
        assert!(matches!(
            identity.os.as_str(),
            "linux" | "windows" | "macos"
        ));
    }
}
