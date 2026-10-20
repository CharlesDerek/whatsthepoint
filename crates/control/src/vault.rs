use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::{io::Write, path::Path};
use zeroize::Zeroizing;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    pub nonce: String,
    pub ciphertext: String,
}
pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> anyhow::Result<Sealed> {
    ensure!(plaintext.len() <= crate::MAX_BODY, "Vault input too large");
    let nonce = crate::random_hex(12);
    let bytes = hex::decode(&nonce)?;
    let ciphertext = Aes256Gcm::new_from_slice(&crate::derive_key(key, b"wtp.aead.v1"))?
        .encrypt(
            Nonce::from_slice(&bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
    Ok(Sealed {
        nonce,
        ciphertext: hex::encode(ciphertext),
    })
}
pub fn open(key: &[u8; 32], value: &Sealed, aad: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    ensure!(
        crate::is_hex(&value.nonce, 12) && value.ciphertext.len() <= crate::MAX_BODY * 2 + 32,
        "Invalid encrypted vault"
    );
    let nonce = hex::decode(&value.nonce)?;
    let bytes = hex::decode(&value.ciphertext)?;
    let value = Aes256Gcm::new_from_slice(&crate::derive_key(key, b"wtp.aead.v1"))?
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: &bytes, aad })
        .map_err(|_| anyhow::anyhow!("Wrong password, identity, or modified encrypted vault"))?;
    Ok(Zeroizing::new(value))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordVault {
    version: u32,
    salt: String,
    sealed: Sealed,
}
fn derive(password: &str, salt: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    ensure!(
        password.len() >= 12 && password.len() <= 1024 && crate::is_hex(salt, 16),
        "Use a vault passphrase of 12–1024 bytes"
    );
    let mut key = Zeroizing::new([0; 32]);
    let params = argon2::Params::new(65536, 3, 1, Some(32)).map_err(|e| anyhow::anyhow!(e))?;
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &hex::decode(salt)?, key.as_mut())
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok(key)
}
pub fn save_pool(
    path: &Path,
    password: &str,
    credentials: &[crate::Credential],
) -> anyhow::Result<()> {
    ensure!(credentials.len() <= 128, "Credential pool full");
    let salt = crate::random_hex(16);
    let key = derive(password, &salt)?;
    let bytes = Zeroizing::new(serde_json::to_vec(credentials)?);
    let sealed = seal(&key, &bytes, b"wtp.credential-pool.v1")?;
    atomic_write(
        path,
        &serde_json::to_vec(&PasswordVault {
            version: 1,
            salt,
            sealed,
        })?,
    )
}
pub fn load_pool(path: &Path, password: &str) -> anyhow::Result<Vec<crate::Credential>> {
    ensure!(
        std::fs::metadata(path)?.len() <= (crate::MAX_BODY * 2) as u64,
        "Vault too large"
    );
    let bytes = std::fs::read(path)?;
    ensure!(bytes.len() <= crate::MAX_BODY * 2, "Vault too large");
    let value: PasswordVault = serde_json::from_slice(&bytes)?;
    ensure!(value.version == 1, "Unsupported vault version");
    let key = derive(password, &value.salt)?;
    let bytes = open(&key, &value.sealed, b"wtp.credential-pool.v1")?;
    let credentials: Vec<crate::Credential> = serde_json::from_slice(&bytes)?;
    ensure!(credentials.len() <= 128, "Credential pool full");
    Ok(credentials)
}
pub fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temp = parent.join(format!(".wtp-{}.tmp", crate::random_hex(16)));
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temp).context("Create protected file")?;
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
