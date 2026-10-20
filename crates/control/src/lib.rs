//! Authenticated control messages inside pinned, hybrid post-quantum TLS 1.3.
//! MAC addresses are public identity context, never cryptographic secret material.
pub mod client;
pub mod identity;
pub mod vault;
use anyhow::{Context, ensure};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub const MAX_BODY: usize = 4 * 1024 * 1024;
pub const CLOCK_WINDOW: i64 = 60;
pub const SUITE: &str = "TLS1.3/X25519MLKEM768/AES256GCM";
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub fn random_hex(bytes: usize) -> String {
    let mut value = vec![0; bytes];
    rand::rngs::OsRng.fill_bytes(&mut value);
    hex::encode(value)
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn is_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
pub fn key(value: &str) -> anyhow::Result<[u8; 32]> {
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Expected a 256-bit secret"))
}
pub(crate) fn derive_key(key: &[u8; 32], context: &[u8]) -> [u8; 32] {
    let mut derived = [0; 32];
    hkdf::Hkdf::<Sha256>::new(Some(b"wtp.keys.v1"), key)
        .expand(context, &mut derived)
        .expect("valid HKDF output length");
    derived
}
fn message(domain: &str, value: &impl Serialize) -> anyhow::Result<Vec<u8>> {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(serde_json::to_vec(value)?);
    Ok(bytes)
}
pub fn authenticate(secret: &str, domain: &str, value: &impl Serialize) -> anyhow::Result<String> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&derive_key(&key(secret)?, b"wtp.hmac.v1"))?;
    mac.update(&message(domain, value)?);
    Ok(hex::encode(mac.finalize().into_bytes()))
}
pub fn verify_mac(
    secret: &str,
    domain: &str,
    value: &impl Serialize,
    signature: &str,
) -> anyhow::Result<()> {
    ensure!(is_hex(signature, 32), "Invalid authenticator");
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&derive_key(&key(secret)?, b"wtp.hmac.v1"))?;
    mac.update(&message(domain, value)?);
    mac.verify_slice(&hex::decode(signature)?)
        .context("Authentication failed")
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Master {
    pub id: String,
    pub name: String,
    pub origin: String,
    pub control: std::net::SocketAddr,
    pub mac_addresses: Vec<String>,
    pub certificate_pem: String,
    pub policy_key: String,
}
impl Master {
    pub fn validate(&self) -> anyhow::Result<()> {
        let url = url::Url::parse(&self.origin)?;
        ensure!(
            is_hex(&self.id, 16) && is_hex(&self.policy_key, 32) && self.name.len() <= 128,
            "Invalid master identity"
        );
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
                && !self.origin.ends_with('/')
                && url.port_or_known_default() == Some(self.control.port()),
            "Invalid master HTTPS origin"
        );
        ensure!(
            !self.control.ip().is_unspecified() && !self.control.ip().is_multicast(),
            "Invalid control address"
        );
        ensure!(
            self.certificate_pem.len() <= 16384 && !self.certificate_pem.is_empty(),
            "Invalid master certificate"
        );
        validate_macs(&self.mac_addresses)?;
        Ok(())
    }
    pub fn fingerprint(&self) -> String {
        digest(&serde_json::to_vec(self).expect("serializable identity"))
    }
}
pub fn validate_macs(macs: &[String]) -> anyhow::Result<()> {
    ensure!(macs.len() <= 32, "Too many MAC addresses");
    for mac in macs {
        ensure!(
            mac.len() == 17
                && mac.split(':').count() == 6
                && mac
                    .split(':')
                    .all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit())),
            "Invalid MAC identity"
        );
    }
    ensure!(
        macs.windows(2).all(|pair| pair[0] < pair[1]),
        "MAC identities must be sorted and unique"
    );
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub installation_id: String,
    pub platform: String,
    pub account_id: String,
    pub hostname: String,
    pub mac_addresses: Vec<String>,
}
impl Node {
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            is_hex(&self.installation_id, 16)
                && matches!(self.platform.as_str(), "linux" | "windows" | "macos")
                && !self.account_id.is_empty()
                && self.account_id.len() <= 256
                && self.hostname.len() <= 256,
            "Invalid node identity"
        );
        validate_macs(&self.mac_addresses)
    }
    pub fn fingerprint(&self, master: &Master) -> String {
        digest(
            &message("wtp.node.v1", &(master.fingerprint(), self)).expect("serializable identity"),
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairBundle {
    pub master: Master,
    pub role: String,
    pub endpoint_id: Option<String>,
    pub ticket_id: String,
    pub secret: String,
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairRequest {
    pub ticket_id: String,
    pub master_hash: String,
    pub node: Node,
    pub nonce: String,
    pub issued_at: i64,
    pub proof: String,
}
impl PairRequest {
    fn unsigned(&self) -> impl Serialize + '_ {
        (
            &self.ticket_id,
            &self.master_hash,
            &self.node,
            &self.nonce,
            self.issued_at,
        )
    }
    pub fn new(bundle: &PairBundle, node: Node) -> anyhow::Result<Self> {
        bundle.master.validate()?;
        node.validate()?;
        ensure!(bundle.expires_at > now(), "Pairing invitation expired");
        let mut request = Self {
            ticket_id: bundle.ticket_id.clone(),
            master_hash: bundle.master.fingerprint(),
            node,
            nonce: random_hex(32),
            issued_at: now(),
            proof: String::new(),
        };
        let proof = authenticate(&bundle.secret, "wtp.pair.request.v1", &request.unsigned())?;
        request.proof = proof;
        Ok(request)
    }
    pub fn verify(&self, secret: &str, master: &Master, at: i64) -> anyhow::Result<()> {
        self.node.validate()?;
        ensure!(
            is_hex(&self.ticket_id, 16)
                && is_hex(&self.nonce, 32)
                && self.master_hash == master.fingerprint()
                && self.issued_at.abs_diff(at) <= CLOCK_WINDOW as u64,
            "Invalid pairing context or timestamp"
        );
        verify_mac(secret, "wtp.pair.request.v1", &self.unsigned(), &self.proof)
    }
    pub fn aad(&self) -> Vec<u8> {
        message("wtp.pair.response.v1", &self.unsigned()).expect("serializable pairing")
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub principal_id: String,
    pub secret: String,
    pub master: Master,
    pub node: Node,
    pub node_hash: String,
    pub role: String,
    pub endpoint_id: Option<String>,
    pub expires_at: i64,
}
impl Credential {
    pub fn validate(&self) -> anyhow::Result<()> {
        self.master.validate()?;
        self.node.validate()?;
        key(&self.secret)?;
        ensure!(
            is_hex(&self.principal_id, 16)
                && self.node_hash == self.node.fingerprint(&self.master)
                && self.expires_at > now()
                && matches!(self.role.as_str(), "console" | "agent"),
            "Invalid or expired paired credential"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub principal_id: String,
    pub master_hash: String,
    pub node_hash: String,
    pub nonce: String,
    pub issued_at: i64,
    pub method: String,
    pub path: String,
    pub body: String,
    pub mac: String,
}
impl Request {
    fn unsigned(&self) -> impl Serialize + '_ {
        (
            &self.principal_id,
            &self.master_hash,
            &self.node_hash,
            &self.nonce,
            self.issued_at,
            &self.method,
            &self.path,
            digest(self.body.as_bytes()),
        )
    }
    pub fn new(
        credential: &Credential,
        method: &str,
        path: &str,
        body: String,
    ) -> anyhow::Result<Self> {
        credential.validate()?;
        let mut request = Self {
            principal_id: credential.principal_id.clone(),
            master_hash: credential.master.fingerprint(),
            node_hash: credential.node_hash.clone(),
            nonce: random_hex(32),
            issued_at: now(),
            method: method.into(),
            path: path.into(),
            body,
            mac: String::new(),
        };
        request.validate(now())?;
        let mac = authenticate(
            &credential.secret,
            "wtp.control.request.v1",
            &request.unsigned(),
        )?;
        request.mac = mac;
        Ok(request)
    }
    pub fn validate(&self, at: i64) -> anyhow::Result<()> {
        ensure!(
            is_hex(&self.principal_id, 16)
                && is_hex(&self.master_hash, 32)
                && is_hex(&self.node_hash, 32)
                && is_hex(&self.nonce, 32)
                && self.issued_at.abs_diff(at) <= CLOCK_WINDOW as u64,
            "Invalid request identity, nonce, or timestamp"
        );
        ensure!(
            matches!(self.method.as_str(), "GET" | "POST" | "DELETE")
                && self.path.starts_with('/')
                && self.path.len() <= 8192
                && !self.path.contains(['\r', '\n', '#'])
                && self.body.len() <= MAX_BODY,
            "Invalid control operation"
        );
        Ok(())
    }
    pub fn verify(
        &self,
        secret: &str,
        master_hash: &str,
        node_hash: &str,
        at: i64,
    ) -> anyhow::Result<()> {
        self.validate(at)?;
        ensure!(
            self.master_hash == master_hash && self.node_hash == node_hash,
            "Principal binding mismatch"
        );
        verify_mac(
            secret,
            "wtp.control.request.v1",
            &self.unsigned(),
            &self.mac,
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub nonce: String,
    pub status: u16,
    pub body: String,
    pub mac: String,
}
impl Response {
    pub fn new(secret: &str, request: &Request, status: u16, body: String) -> anyhow::Result<Self> {
        ensure!(body.len() <= MAX_BODY, "Response exceeds limit");
        let mac = authenticate(
            secret,
            "wtp.control.response.v1",
            &(&request.mac, &request.nonce, status, &body),
        )?;
        Ok(Self {
            nonce: request.nonce.clone(),
            status,
            body,
            mac,
        })
    }
    pub fn verify(&self, secret: &str, request: &Request) -> anyhow::Result<()> {
        ensure!(
            self.nonce == request.nonce
                && self.body.len() <= MAX_BODY
                && (100..=599).contains(&self.status),
            "Invalid or replayed response"
        );
        verify_mac(
            secret,
            "wtp.control.response.v1",
            &(&request.mac, &self.nonce, self.status, &self.body),
            &self.mac,
        )
    }
}

impl std::fmt::Debug for PairBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairBundle")
            .field("master", &self.master.id)
            .field("ticket_id", &self.ticket_id)
            .field("secret", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}
