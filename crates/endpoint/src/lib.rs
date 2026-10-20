//! Signed, bounded, replay-resistant endpoint policy and platform rule compilers.
//! No policy string is ever evaluated as a shell command.
pub mod platform;
pub mod runtime;
use anyhow::{Context, ensure};
pub use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    path::Path,
};

pub const POLICY_DOMAIN: &str = "wtp.endpoint.policy.v1";
pub const RELEASE_DOMAIN: &str = "wtp.release.file.v1";
pub const MAX_ENVELOPE: u64 = 262144;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    pub dns_servers: Vec<IpAddr>,
    pub allowed_tcp: Vec<SocketAddr>,
    pub allowed_udp: Vec<SocketAddr>,
    /// Only these physical interface names may carry non-loopback traffic.
    pub interfaces: Vec<String>,
    pub dhcp: bool,
}
impl NetworkPolicy {
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.dns_servers.len() <= 8
                && self.allowed_tcp.len() <= 128
                && self.allowed_udp.len() <= 32,
            "Too many network destinations"
        );
        ensure!(
            !self.interfaces.is_empty() && self.interfaces.len() <= 16,
            "Specify 1–16 approved physical interfaces"
        );
        for name in &self.interfaces {
            ensure!(
                !name.is_empty()
                    && name.len() <= 64
                    && name.bytes().all(
                        |b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b' ')
                    ),
                "Invalid interface name"
            );
            let lower = name.to_ascii_lowercase();
            ensure!(
                !["tun", "tap", "utun", "wg", "ppp", "ipsec"]
                    .iter()
                    .any(|p| lower.starts_with(p)),
                "Tunnel interfaces cannot be approved uplinks"
            );
        }
        for ip in self
            .dns_servers
            .iter()
            .copied()
            .chain(self.allowed_tcp.iter().map(SocketAddr::ip))
            .chain(self.allowed_udp.iter().map(SocketAddr::ip))
        {
            ensure!(
                !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback(),
                "Use explicit non-loopback unicast destination IPs"
            );
        }
        for addr in self.allowed_tcp.iter().chain(&self.allowed_udp) {
            ensure!(
                addr.port() > 0 && !matches!(addr.port(), 53 | 853),
                "DNS ports are reserved for approved resolvers; DoT is blocked"
            );
            if let SocketAddr::V6(addr) = addr {
                ensure!(
                    addr.scope_id() == 0 && addr.flowinfo() == 0,
                    "Scoped IPv6 sockets are unsupported"
                );
            }
        }
        Ok(())
    }
    pub fn quarantine(&self, control: SocketAddr) -> Self {
        Self {
            dns_servers: vec![],
            allowed_tcp: vec![control],
            allowed_udp: vec![],
            interfaces: self.interfaces.clone(),
            dhcp: self.dhcp,
        }
    }
    pub fn tcp(&self) -> BTreeSet<SocketAddr> {
        self.allowed_tcp
            .iter()
            .copied()
            .chain(self.dns_servers.iter().map(|ip| SocketAddr::new(*ip, 53)))
            .collect()
    }
    pub fn udp(&self) -> BTreeSet<SocketAddr> {
        self.allowed_udp
            .iter()
            .copied()
            .chain(self.dns_servers.iter().map(|ip| SocketAddr::new(*ip, 53)))
            .collect()
    }
    pub fn digest(&self) -> String {
        hex::encode(Sha256::digest(
            serde_json::to_vec(self).expect("serializable policy"),
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub endpoint_id: String,
    pub platform: String,
    pub revision: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub network: NetworkPolicy,
}
impl Policy {
    pub fn validate(&self, endpoint_id: &str, platform: &str, now: i64) -> anyhow::Result<()> {
        ensure!(
            self.endpoint_id == endpoint_id && self.platform == platform,
            "Policy belongs to another endpoint or platform"
        );
        ensure!(self.revision > 0, "Policy revision must be positive");
        ensure!(
            self.issued_at <= now + 30
                && self.expires_at > now
                && self.expires_at > self.issued_at
                && self.expires_at - self.issued_at <= 3600,
            "Policy expired or validity interval is invalid"
        );
        self.network.validate()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub domain: String,
    pub payload: String,
    pub signature: String,
}
fn signing_message(domain: &str, payload: &[u8]) -> Vec<u8> {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(payload);
    bytes
}
pub fn generate_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}
pub fn private_key(hex_key: &str) -> anyhow::Result<SigningKey> {
    let bytes: [u8; 32] = hex::decode(hex_key.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Expected a 32-byte private key"))?;
    Ok(SigningKey::from_bytes(&bytes))
}
pub fn public_key(hex_key: &str) -> anyhow::Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(hex_key.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Expected a 32-byte public key"))?;
    let key = VerifyingKey::from_bytes(&bytes)?;
    ensure!(!key.is_weak(), "Weak public key");
    Ok(key)
}
pub fn sign<T: Serialize>(value: &T, domain: &str, key: &SigningKey) -> anyhow::Result<Envelope> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= 65536, "Signed payload exceeds 64 KB");
    Ok(Envelope {
        domain: domain.into(),
        payload: hex::encode(&bytes),
        signature: hex::encode(key.sign(&signing_message(domain, &bytes)).to_bytes()),
    })
}
pub fn verify<T: DeserializeOwned>(
    envelope: &Envelope,
    domain: &str,
    key: &VerifyingKey,
) -> anyhow::Result<T> {
    ensure!(
        envelope.domain == domain
            && envelope.payload.len() <= 131072
            && envelope.signature.len() == 128,
        "Invalid signature domain or payload size"
    );
    let payload = hex::decode(&envelope.payload)?;
    let signature = Signature::from_slice(&hex::decode(&envelope.signature)?)?;
    key.verify_strict(&signing_message(domain, &payload), &signature)
        .context("Signature verification failed")?;
    Ok(serde_json::from_slice(&payload)?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub endpoint_id: String,
    pub platform: String,
    pub portal: String,
    pub control: SocketAddr,
    pub token: String,
    pub public_key: String,
    /// Bootstrap uplinks are administrator-controlled; never learned from an untrusted response.
    pub interfaces: Vec<String>,
    pub dhcp: bool,
}
impl AgentConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.endpoint_id.len() == 32 && self.endpoint_id.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid endpoint ID"
        );
        ensure!(
            matches!(self.platform.as_str(), "linux" | "windows" | "macos"),
            "Unsupported platform"
        );
        ensure!(
            self.token.len() == 64 && self.token.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid endpoint token"
        );
        public_key(&self.public_key)?;
        let origin = url::Url::parse(&self.portal)?;
        ensure!(
            origin.scheme() == "https"
                && origin.host_str().is_some()
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.path() == "/"
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.port_or_known_default() == Some(self.control.port()),
            "Portal must be an HTTPS origin with the control endpoint's port"
        );
        self.quarantine().validate()
    }
    pub fn quarantine(&self) -> NetworkPolicy {
        NetworkPolicy {
            dns_servers: vec![],
            allowed_tcp: vec![self.control],
            allowed_udp: vec![],
            interfaces: self.interfaces.clone(),
            dhcp: self.dhcp,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Watermark {
    pub revision: u64,
    pub digest: String,
    pub last_time: i64,
}
impl Watermark {
    pub fn accept(&self, policy: &Policy, config: &AgentConfig, now: i64) -> anyhow::Result<Self> {
        config.validate()?;
        ensure!(now + 30 >= self.last_time, "System clock moved backwards");
        policy.validate(&config.endpoint_id, &config.platform, now)?;
        ensure!(
            policy.network.allowed_tcp.contains(&config.control),
            "Policy would disconnect its management endpoint"
        );
        ensure!(
            policy.network.interfaces == config.interfaces,
            "Uplink changes require local administrator re-enrollment"
        );
        let digest = policy.network.digest();
        ensure!(
            policy.revision >= self.revision
                && (policy.revision != self.revision || self.digest == digest),
            "Policy rollback or revision reuse rejected"
        );
        Ok(Self {
            revision: policy.revision,
            digest,
            last_time: now,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileClaim {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}
pub fn file_claim(path: &Path) -> anyhow::Result<FileClaim> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut total = 0;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        total += n as u64;
    }
    Ok(FileClaim {
        name: path
            .file_name()
            .context("Artifact filename missing")?
            .to_string_lossy()
            .into_owned(),
        bytes: total,
        sha256: hex::encode(hash.finalize()),
    })
}
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
