use anyhow::{Context, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub dns_bind: SocketAddr,
    pub http_bind: SocketAddr,
    pub public_origin: String,
    pub tls_certificate: Option<std::path::PathBuf>,
    pub tls_private_key: Option<std::path::PathBuf>,
    pub master_name: String,
    pub allowed_clients: Vec<IpNet>,
    pub upstreams: Vec<Upstream>,
    pub cache_entries: usize,
    pub query_log: bool,
    pub retention_days: u32,
    pub max_log_entries: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub url: String,
    // Avoid a circular dependency when the OS uses this resolver.
    pub bootstrap: SocketAddr,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dns_bind: "127.0.0.1:5354".parse().unwrap(),
            http_bind: "127.0.0.1:8080".parse().unwrap(),
            public_origin: "http://127.0.0.1:8080".into(),
            tls_certificate: None,
            tls_private_key: None,
            master_name: "What’s the Point master".into(),
            allowed_clients: vec!["127.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()],
            upstreams: vec![
                Upstream {
                    url: "https://dns.quad9.net/dns-query".into(),
                    bootstrap: "9.9.9.9:443".parse().unwrap(),
                },
                Upstream {
                    url: "https://dns.quad9.net/dns-query".into(),
                    bootstrap: "149.112.112.112:443".parse().unwrap(),
                },
            ],
            cache_entries: 10_000,
            query_log: true,
            retention_days: 7,
            max_log_entries: 100_000,
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let config: Self = match path {
            Some(path) => {
                toml::from_str(&std::fs::read_to_string(path).context("read configuration")?)?
            }
            None => Self::default(),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let origin = reqwest::Url::parse(&self.public_origin)?;
        if !matches!(origin.scheme(), "http" | "https")
            || origin.host_str().is_none()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || self.public_origin.ends_with('/')
        {
            bail!("public_origin must be an HTTP(S) origin without a trailing slash");
        }
        if origin.scheme() == "http"
            && (!self.http_bind.ip().is_loopback()
                || !matches!(origin.host_str(), Some("127.0.0.1" | "[::1]" | "localhost")))
        {
            bail!("remote administration requires an HTTPS public_origin and a TLS reverse proxy");
        }
        if self.tls_certificate.is_some() != self.tls_private_key.is_some() {
            bail!("Configure both TLS certificate and private key");
        }
        if self.tls_certificate.is_some()
            && (origin.scheme() != "https"
                || origin.port_or_known_default() != Some(self.http_bind.port()))
        {
            bail!("Native TLS requires a matching HTTPS origin and port");
        }
        if self.tls_certificate.is_none() && !self.http_bind.ip().is_loopback() {
            bail!(
                "LAN console binding requires native TLS; reverse-proxy HTTP must remain on loopback"
            );
        }
        if self.master_name.is_empty() || self.master_name.len() > 128 {
            bail!("Master name must be 1–128 bytes");
        }
        if self.upstreams.is_empty() || self.upstreams.len() > 4 {
            bail!("configure between one and four HTTPS upstreams");
        }
        for upstream in &self.upstreams {
            let url = reqwest::Url::parse(&upstream.url)?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
                || url.port_or_known_default() != Some(upstream.bootstrap.port())
            {
                bail!("upstreams require HTTPS and a bootstrap address with a matching port");
            }
        }
        if self.allowed_clients.is_empty()
            || self.cache_entries == 0
            || self.cache_entries > 1_000_000
            || self.retention_days > 365
            || self.max_log_entries == 0
            || self.max_log_entries > 10_000_000
        {
            bail!("invalid client ACL, cache capacity, or log retention");
        }
        Ok(())
    }
}
