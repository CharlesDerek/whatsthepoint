use anyhow::{Context, ensure};
use axum::{Extension, Router, extract::ConnectInfo};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
#[derive(Clone, Debug)]
pub struct TlsPeer {
    pub suite: String,
}
pub fn server_config(cert: &Path, key: &Path) -> anyhow::Result<rustls::ServerConfig> {
    let certs = rustls_pemfile::certs(&mut std::fs::read(cert)?.as_slice())
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::fs::read(key)?.as_slice())?
        .context("Missing TLS private key")?;
    let mut config =
        rustls::ServerConfig::builder_with_provider(Arc::new(wtp_control::client::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}
pub async fn serve(
    listener: TcpListener,
    router: Router,
    config: rustls::ServerConfig,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let slots = Arc::new(tokio::sync::Semaphore::new(128));
    let tasks = TaskTracker::new();
    loop {
        let accepted =
            tokio::select! {_ = cancel.cancelled()=>break,accepted=listener.accept()=>accepted?};
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let (stream, peer) = accepted;
        let acceptor = acceptor.clone();
        let router = router.clone();
        let cancellation = cancel.clone();
        tasks.spawn(async move {
            let _permit=permit;
            let Ok(Ok(tls))=tokio::time::timeout(Duration::from_secs(10),acceptor.accept(stream)).await else {return};
            let group=tls.get_ref().1.negotiated_key_exchange_group().map(|g|g.name());
            if group!=Some(rustls::NamedGroup::X25519MLKEM768){return;}
            let service=TowerToHyperService::new(router.layer(Extension(ConnectInfo::<SocketAddr>(peer))).layer(Extension(TlsPeer{suite:wtp_control::SUITE.into()})));
            let builder=Builder::new(TokioExecutor::new());let connection=builder.serve_connection(TokioIo::new(tls),service);tokio::pin!(connection);
            tokio::select!{result=&mut connection=>{if let Err(error)=result{tracing::debug!(%error,"TLS connection ended");}},_ = cancellation.cancelled()=>{connection.as_mut().graceful_shutdown();let _=tokio::time::timeout(Duration::from_secs(5),&mut connection).await;}}
        });
    }
    tasks.close();
    tasks.wait().await;
    Ok(())
}
pub fn provision(
    data: &Path,
    address: std::net::IpAddr,
    port: u16,
    dns_port: u16,
    prefix: u8,
) -> anyhow::Result<crate::config::Config> {
    ensure!(
        !address.is_loopback()
            && !address.is_unspecified()
            && !address.is_multicast()
            && port != 0
            && dns_port != 0,
        "Choose a concrete LAN address and ports"
    );
    std::fs::create_dir_all(data)?;
    let cert = data.join("master.crt");
    let key = data.join("master.key");
    ensure!(
        !cert.exists() && !key.exists(),
        "TLS identity exists; keep it or explicitly rotate and re-pair clients"
    );
    let generated = rcgen::generate_simple_self_signed(vec![address.to_string()])?;
    wtp_control::vault::atomic_write(&key, generated.signing_key.serialize_pem().as_bytes())?;
    wtp_control::vault::atomic_write(&cert, generated.cert.pem().as_bytes())?;
    let socket = SocketAddr::new(address, port);
    let config = crate::config::Config {
        dns_bind: SocketAddr::new(address, dns_port),
        http_bind: socket,
        public_origin: format!("https://{socket}"),
        allowed_clients: vec![ipnet::IpNet::new(address, prefix)?.trunc()],
        tls_certificate: Some(cert.canonicalize()?),
        tls_private_key: Some(key.canonicalize()?),
        master_name: "What's the Point master".into(),
        ..Default::default()
    };
    config.validate()?;
    Ok(config)
}
