use crate::{
    Credential, MAX_BODY, Master, Node, PairBundle, PairRequest, Request, Response, vault,
};
use anyhow::{Context, ensure};
use std::{io::Read, sync::Arc, time::Duration};
pub fn provider() -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384];
    provider
}
pub fn tls_config(master: &Master) -> anyhow::Result<rustls::ClientConfig> {
    master.validate()?;
    let mut roots = rustls::RootCertStore::empty();
    let certs = rustls_pemfile::certs(&mut master.certificate_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(
        certs.len() == 1,
        "Pairing requires one pinned trust certificate"
    );
    roots.add(certs[0].clone())?;
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}
pub fn http(master: &Master) -> anyhow::Result<reqwest::blocking::Client> {
    let origin = url::Url::parse(&master.origin)?;
    let host = origin
        .host_str()
        .context("Missing master host")?
        .trim_matches(['[', ']']);
    Ok(reqwest::blocking::Client::builder()
        .use_preconfigured_tls(tls_config(master)?)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .resolve(host, master.control)
        .build()?)
}
fn post<T: serde::Serialize, R: serde::de::DeserializeOwned>(
    master: &Master,
    path: &str,
    body: &T,
) -> anyhow::Result<R> {
    let response = http(master)?
        .post(format!("{}{path}", master.origin))
        .header("X-WTP-Request", "1")
        .json(body)
        .send()?
        .error_for_status()?;
    let mut bytes = Vec::new();
    response
        .take((MAX_BODY * 3 + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_BODY * 3, "Response too large");
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn pair(bundle: &PairBundle, node: Node) -> anyhow::Result<Credential> {
    let request = PairRequest::new(bundle, node)?;
    let sealed: vault::Sealed = post(&bundle.master, "/control/pair", &request)?;
    let credential: Credential = serde_json::from_slice(&vault::open(
        &crate::key(&bundle.secret)?,
        &sealed,
        &request.aad(),
    )?)?;
    credential.validate()?;
    ensure!(
        credential.master == bundle.master
            && credential.role == bundle.role
            && credential.endpoint_id == bundle.endpoint_id
            && credential.node_hash == request.node.fingerprint(&bundle.master),
        "Pairing response identity mismatch"
    );
    Ok(credential)
}
pub fn send(
    credential: &Credential,
    method: &str,
    path: &str,
    body: String,
) -> anyhow::Result<Response> {
    let request = Request::new(credential, method, path, body)?;
    let response: Response = post(&credential.master, "/control/request", &request)?;
    response.verify(&credential.secret, &request)?;
    Ok(response)
}
