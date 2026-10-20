use crate::App;
use anyhow::{Context, bail};
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::RData,
};
use lru::LruCache;
use serde::Serialize;
use std::{
    net::SocketAddr,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::{Mutex, Semaphore, mpsc},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

struct Cached {
    message: Message,
    inserted: Instant,
    ttl: u32,
}
struct Upstream {
    url: String,
    client: reqwest::Client,
}

#[derive(Serialize)]
pub struct QueryEvent {
    pub at: i64,
    pub client: String,
    pub domain: String,
    pub qtype: String,
    pub decision: String,
    pub reason: String,
    pub elapsed_ms: i64,
    pub cached: bool,
    pub rcode: String,
}

pub struct Resolver {
    app: App,
    upstreams: Vec<Upstream>,
    cache: Mutex<LruCache<Vec<u8>, Cached>>,
    events: mpsc::Sender<QueryEvent>,
}

impl Resolver {
    pub fn new(app: App, events: mpsc::Sender<QueryEvent>) -> anyhow::Result<Self> {
        let upstreams = app
            .config
            .upstreams
            .iter()
            .map(|u| {
                let url = reqwest::Url::parse(&u.url)?;
                let client = reqwest::Client::builder()
                    .https_only(true)
                    .no_proxy()
                    .resolve(
                        url.host_str().context("missing upstream host")?,
                        u.bootstrap,
                    )
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(3))
                    .connect_timeout(Duration::from_secs(2))
                    .build()?;
                Ok(Upstream {
                    url: u.url.clone(),
                    client,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let cache = Mutex::new(LruCache::new(
            NonZeroUsize::new(app.config.cache_entries).unwrap(),
        ));
        Ok(Self {
            app,
            upstreams,
            cache,
            events,
        })
    }

    pub async fn resolve(&self, bytes: &[u8], peer: SocketAddr) -> anyhow::Result<Vec<u8>> {
        let start = Instant::now();
        let request = Message::from_vec(bytes)?;
        if request.metadata.message_type != MessageType::Query {
            bail!("not a DNS query");
        }
        if !self
            .app
            .config
            .allowed_clients
            .iter()
            .any(|net| net.contains(&peer.ip()))
        {
            return reply(&request, ResponseCode::Refused)
                .to_vec()
                .map_err(Into::into);
        }
        if request.metadata.op_code != OpCode::Query {
            return reply(&request, ResponseCode::NotImp)
                .to_vec()
                .map_err(Into::into);
        }
        if request
            .edns
            .as_ref()
            .is_some_and(|edns| edns.version() != 0)
        {
            return reply(&request, ResponseCode::BADVERS)
                .to_vec()
                .map_err(Into::into);
        }
        if request.queries.len() != 1
            || !request.answers.is_empty()
            || !request.authorities.is_empty()
        {
            return reply(&request, ResponseCode::FormErr)
                .to_vec()
                .map_err(Into::into);
        }
        let query = &request.queries[0];
        if query.query_class() != hickory_proto::rr::DNSClass::IN
            || matches!(
                query.query_type(),
                hickory_proto::rr::RecordType::AXFR
                    | hickory_proto::rr::RecordType::IXFR
                    | hickory_proto::rr::RecordType::ANY
            )
        {
            return reply(&request, ResponseCode::Refused)
                .to_vec()
                .map_err(Into::into);
        }
        let domain = query.name().to_ascii().trim_end_matches('.').to_lowercase();
        let decision = self.app.policy.read().await.decide(&domain);
        let mut reason = decision.reason;
        let mut status = if decision.blocked {
            "blocked"
        } else {
            "allowed"
        };
        let mut cached = false;
        let mut response = if decision.blocked {
            reply(&request, ResponseCode::NXDomain)
        } else {
            match self.forward(&request).await {
                Ok((answer, hit)) => {
                    cached = hit;
                    // Evaluate aliases on every cache hit too: policy updates apply immediately.
                    let policy = self.app.policy.read().await;
                    let blocked_alias = answer.answers.iter().find_map(|record| {
                        let target = match &record.data {
                            RData::CNAME(name) => Some(name.0.to_ascii()),
                            RData::HTTPS(https) => Some(https.0.target_name.to_ascii()),
                            RData::SVCB(svcb) => Some(svcb.target_name.to_ascii()),
                            _ => None,
                        }?;
                        let decision = policy.decide(&target);
                        decision.blocked.then_some(decision)
                    });
                    if let Some(blocked) = blocked_alias {
                        reason = format!("Alias: {}", blocked.reason);
                        status = "blocked";
                        reply(&request, ResponseCode::NXDomain)
                    } else {
                        answer
                    }
                }
                Err(error) => {
                    tracing::debug!(%error, "all encrypted upstreams failed");
                    status = "error";
                    reason = "Encrypted upstream unavailable".into();
                    reply(&request, ResponseCode::ServFail)
                }
            }
        };
        response.metadata.id = request.metadata.id;
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        // Return EDNS only when requested, with our actual UDP payload limit.
        response.edns = request.edns.as_ref().map(|request_edns| {
            let mut edns = hickory_proto::op::Edns::new();
            edns.set_max_payload(1232)
                .set_dnssec_ok(request_edns.flags().dnssec_ok);
            edns
        });
        if self.app.config.query_log {
            // A slow/full audit queue never blocks DNS; bounded logging is deliberately lossy.
            let _ = self.events.try_send(QueryEvent {
                at: crate::now(),
                client: peer.ip().to_string(),
                domain,
                qtype: query.query_type().to_string(),
                decision: status.into(),
                reason,
                elapsed_ms: start.elapsed().as_millis() as i64,
                cached,
                rcode: response.metadata.response_code.to_string(),
            });
        }
        response.to_vec().map_err(Into::into)
    }

    async fn forward(&self, request: &Message) -> anyhow::Result<(Message, bool)> {
        // Strip client EDNS options (including ECS), extra records, and client-provided flags.
        let mut clean = Message::query();
        clean.metadata.id = 0;
        clean.metadata.recursion_desired = true;
        clean.metadata.checking_disabled = request.metadata.checking_disabled;
        clean.add_query(request.queries[0].clone());
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(1232)
            .set_dnssec_ok(request.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok));
        clean.set_edns(edns);
        let key = clean.to_vec()?;
        {
            let mut cache = self.cache.lock().await;
            if let Some(entry) = cache.get(&key) {
                let age = entry.inserted.elapsed().as_secs() as u32;
                if age < entry.ttl {
                    let mut answer = entry.message.clone();
                    for record in &mut answer.answers {
                        record.ttl = record.ttl.saturating_sub(age);
                    }
                    for record in &mut answer.authorities {
                        record.ttl = record.ttl.saturating_sub(age);
                    }
                    for record in &mut answer.additionals {
                        record.ttl = record.ttl.saturating_sub(age);
                    }
                    return Ok((answer, true));
                }
            }
            cache.pop(&key);
        }
        for upstream in &self.upstreams {
            match fetch(upstream, &key, &clean).await {
                Ok(answer) => {
                    let ttl = answer
                        .answers
                        .iter()
                        .chain(&answer.authorities)
                        .chain(&answer.additionals)
                        .map(|r| r.ttl)
                        .min()
                        .unwrap_or(0)
                        .min(3600);
                    if ttl > 0
                        && answer.metadata.response_code == ResponseCode::NoError
                        && !answer.metadata.truncation
                        && !answer.answers.is_empty()
                    {
                        self.cache.lock().await.put(
                            key,
                            Cached {
                                message: answer.clone(),
                                inserted: Instant::now(),
                                ttl,
                            },
                        );
                    }
                    return Ok((answer, false));
                }
                Err(error) => tracing::debug!(%error, "upstream attempt failed"),
            }
        }
        bail!("no upstream answered")
    }
}

async fn fetch(upstream: &Upstream, bytes: &[u8], query: &Message) -> anyhow::Result<Message> {
    let mut response = upstream
        .client
        .post(&upstream.url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(bytes.to_vec())
        .send()
        .await?
        .error_for_status()?;
    if response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or("").trim())
        != Some("application/dns-message")
    {
        bail!("invalid DoH content type");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > 65535 {
            bail!("oversized DoH response");
        }
        body.extend_from_slice(&chunk);
    }
    let answer = Message::from_vec(&body)?;
    if answer.metadata.message_type != MessageType::Response
        || answer.metadata.id != 0
        || answer.metadata.op_code != OpCode::Query
        || answer.queries != query.queries
        || answer.metadata.truncation
        || matches!(
            answer.metadata.response_code,
            ResponseCode::ServFail | ResponseCode::Refused
        )
    {
        bail!("invalid or unavailable DoH response");
    }
    Ok(answer)
}

pub fn reply(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = code;
    response.metadata.checking_disabled = request.metadata.checking_disabled;
    if let Some(request_edns) = &request.edns {
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(1232)
            .set_dnssec_ok(request_edns.flags().dnssec_ok);
        response.set_edns(edns);
    }
    for query in &request.queries {
        response.add_query(query.clone());
    }
    response
}

pub fn udp_size(request: &[u8]) -> usize {
    Message::from_vec(request)
        .ok()
        .and_then(|m| m.edns.as_ref().map(|e| e.max_payload() as usize))
        .unwrap_or(512)
        .clamp(512, 1232)
}

pub fn truncate(bytes: Vec<u8>, max: usize) -> anyhow::Result<Vec<u8>> {
    if bytes.len() <= max {
        return Ok(bytes);
    }
    Ok(Message::from_vec(&bytes)?.truncate().to_vec()?)
}

pub async fn serve_udp(
    socket: UdpSocket,
    resolver: Arc<Resolver>,
    cancel: CancellationToken,
    tasks: TaskTracker,
) -> anyhow::Result<()> {
    let socket = Arc::new(socket);
    let slots = Arc::new(Semaphore::new(256));
    let mut buffer = vec![0; 4096];
    loop {
        let (len, peer) = tokio::select! { _ = cancel.cancelled() => break, result = socket.recv_from(&mut buffer) => result? };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let bytes = buffer[..len].to_vec();
        let socket = socket.clone();
        let resolver = resolver.clone();
        tasks.spawn(async move {
            let _permit = permit;
            if let Ok(reply) = resolver
                .resolve(&bytes, peer)
                .await
                .and_then(|reply| truncate(reply, udp_size(&bytes)))
            {
                let _ = socket.send_to(&reply, peer).await;
            }
        });
    }
    Ok(())
}

pub async fn serve_tcp(
    listener: TcpListener,
    resolver: Arc<Resolver>,
    cancel: CancellationToken,
    tasks: TaskTracker,
) -> anyhow::Result<()> {
    let slots = Arc::new(Semaphore::new(128));
    loop {
        let (mut stream, peer) = tokio::select! { _ = cancel.cancelled() => break, result = listener.accept() => result? };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let resolver = resolver.clone();
        let cancel = cancel.clone();
        tasks.spawn(async move {
            let _permit = permit;
            for _ in 0..100 {
                let exchange = async {
                    let len = stream.read_u16().await? as usize;
                    if !(12..=4096).contains(&len) {
                        bail!("invalid query size");
                    }
                    let mut bytes = vec![0; len];
                    stream.read_exact(&mut bytes).await?;
                    let response = resolver.resolve(&bytes, peer).await?;
                    stream.write_u16(response.len().try_into()?).await?;
                    stream.write_all(&response).await?;
                    Ok::<_, anyhow::Error>(())
                };
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = tokio::time::timeout(Duration::from_secs(15), exchange) => {
                        if !matches!(result, Ok(Ok(()))) { break; }
                    }
                }
            }
        });
    }
    Ok(())
}

pub async fn log_writer(pool: sqlx::SqlitePool, mut rx: mpsc::Receiver<QueryEvent>) {
    while let Some(event) = rx.recv().await {
        let result = sqlx::query("INSERT INTO queries(at, client, domain, qtype, decision, reason, elapsed_ms, cached, rcode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(event.at).bind(event.client).bind(event.domain).bind(event.qtype).bind(event.decision)
            .bind(event.reason).bind(event.elapsed_ms).bind(event.cached).bind(event.rcode).execute(&pool).await;
        if let Err(error) = result {
            tracing::warn!(%error, "query log write failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::Query,
        rr::{
            Name, Record, RecordType,
            rdata::{A, CNAME},
        },
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn query(domain: &str) -> Message {
        let mut message = Message::query();
        message.metadata.id = 4123;
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(
            Name::from_ascii(domain).unwrap(),
            RecordType::A,
        ));
        message
    }

    async fn fixture() -> (tempfile::TempDir, Arc<Resolver>, mpsc::Receiver<QueryEvent>) {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::db::open(dir.path()).await.unwrap();
        let app = App::new(pool, crate::config::Config::default())
            .await
            .unwrap();
        let (tx, rx) = mpsc::channel(10);
        (dir, Arc::new(Resolver::new(app, tx).unwrap()), rx)
    }

    #[tokio::test]
    async fn blocked_domains_and_client_acl_never_reach_upstream() {
        let (_dir, resolver, mut rx) = fixture().await;
        let bytes = query("sub.blocked.test").to_vec().unwrap();
        let response = Message::from_vec(
            &resolver
                .resolve(&bytes, "127.0.0.1:5000".parse().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response.metadata.id, 4123);
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert!(!response.metadata.authentic_data);
        assert_eq!(rx.recv().await.unwrap().decision, "blocked");
        let refused = Message::from_vec(
            &resolver
                .resolve(&bytes, "203.0.113.1:5000".parse().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(refused.metadata.response_code, ResponseCode::Refused);
        assert!(
            resolver
                .resolve(b"not dns", "127.0.0.1:5000".parse().unwrap())
                .await
                .is_err()
        );
        let mut multi = query("blocked.test");
        multi.add_query(Query::query(
            Name::from_ascii("example.com").unwrap(),
            RecordType::A,
        ));
        let malformed = Message::from_vec(
            &resolver
                .resolve(&multi.to_vec().unwrap(), "127.0.0.1:5000".parse().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(malformed.metadata.response_code, ResponseCode::FormErr);
    }

    #[tokio::test]
    async fn udp_and_tcp_listeners_answer_real_packets() {
        let (_dir, resolver, _rx) = fixture().await;
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp.local_addr().unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let tracker = TaskTracker::new();
        let udp_task = tokio::spawn(serve_udp(
            udp,
            resolver.clone(),
            cancel.clone(),
            tracker.clone(),
        ));
        let tcp_task = tokio::spawn(serve_tcp(tcp, resolver, cancel.clone(), tracker.clone()));
        let bytes = query("blocked.test").to_vec().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&bytes, udp_addr).await.unwrap();
        let mut buffer = [0; 512];
        let len = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Message::from_vec(&buffer[..len])
                .unwrap()
                .metadata
                .response_code,
            ResponseCode::NXDomain
        );
        let mut client = tokio::net::TcpStream::connect(tcp_addr).await.unwrap();
        for _ in 0..2 {
            client.write_u16(bytes.len() as u16).await.unwrap();
            client.write_all(&bytes).await.unwrap();
            let len = client.read_u16().await.unwrap() as usize;
            client.read_exact(&mut buffer[..len]).await.unwrap();
            assert_eq!(
                Message::from_vec(&buffer[..len])
                    .unwrap()
                    .metadata
                    .response_code,
                ResponseCode::NXDomain
            );
        }
        cancel.cancel();
        udp_task.await.unwrap().unwrap();
        tcp_task.await.unwrap().unwrap();
        tracker.close();
        tracker.wait().await;
    }

    #[tokio::test]
    async fn international_domains_and_edns_are_preserved() {
        let (_dir, resolver, _rx) = fixture().await;
        sqlx::query(
            "INSERT INTO rules(domain, action, created_at) VALUES ('xn--bcher-kva.de','block',0)",
        )
        .execute(&resolver.app.db)
        .await
        .unwrap();
        resolver.app.reload().await.unwrap();
        let mut request = query("xn--bcher-kva.de");
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(4096).set_dnssec_ok(true);
        request.set_edns(edns);
        let peer = "127.0.0.1:5000".parse().unwrap();
        let response = Message::from_vec(
            &resolver
                .resolve(&request.to_vec().unwrap(), peer)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(response.edns.unwrap().max_payload(), 1232);
        request.edns.as_mut().unwrap().set_version(1);
        let response = Message::from_vec(
            &resolver
                .resolve(&request.to_vec().unwrap(), peer)
                .await
                .unwrap(),
        )
        .unwrap();
        // BADVERS and BADSIG share the wire code 16.
        assert_eq!(u16::from(response.metadata.response_code), 16);
    }

    #[test]
    fn oversized_udp_answers_are_truncated_for_tcp_retry() {
        let request = query("example.com");
        let mut answer = reply(&request, ResponseCode::NoError);
        for i in 0..100 {
            answer.add_answer(Record::from_rdata(
                Name::from_ascii(format!("host{i}.example.com")).unwrap(),
                60,
                RData::A(A::new(192, 0, 2, 1)),
            ));
        }
        let bytes = truncate(answer.to_vec().unwrap(), 512).unwrap();
        assert!(bytes.len() <= 512);
        assert!(Message::from_vec(&bytes).unwrap().metadata.truncation);
        assert_eq!(udp_size(&request.to_vec().unwrap()), 512);
    }

    #[tokio::test]
    async fn upstream_failover_cache_ttl_and_alias_policy() {
        let (_dir, original, _rx) = fixture().await;
        let count = Arc::new(AtomicUsize::new(0));
        let counter = count.clone();
        // Test-only HTTP mock. Production construction accepts HTTPS upstreams exclusively.
        let server = axum::Router::new().route(
            "/dns-query",
            axum::routing::post(move |body: axum::body::Bytes| {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::Relaxed);
                    let request = Message::from_vec(&body).unwrap();
                    let mut response = reply(&request, ResponseCode::NoError);
                    let name = request.queries[0].name().clone();
                    if name.to_utf8() == "alias.example." {
                        response.add_answer(Record::from_rdata(
                            name,
                            120,
                            RData::CNAME(CNAME(Name::from_ascii("blocked.test").unwrap())),
                        ));
                    } else {
                        response.add_answer(Record::from_rdata(
                            name,
                            120,
                            RData::A(A::new(192, 0, 2, 1)),
                        ));
                    }
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/dns-message")],
                        response.to_vec().unwrap(),
                    )
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, server).await.unwrap() });
        let failed = axum::Router::new().fallback(|| async { axum::http::StatusCode::BAD_GATEWAY });
        let bad_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bad_addr = bad_listener.local_addr().unwrap();
        let bad_task =
            tokio::spawn(async move { axum::serve(bad_listener, failed).await.unwrap() });
        let (tx, mut rx) = mpsc::channel(10);
        let mut resolver = Resolver::new(original.app.clone(), tx).unwrap();
        resolver.upstreams = vec![
            Upstream {
                url: format!("http://{bad_addr}/dns-query"),
                client: reqwest::Client::new(),
            },
            Upstream {
                url: format!("http://{addr}/dns-query"),
                client: reqwest::Client::new(),
            },
        ];
        let peer = "127.0.0.1:1000".parse().unwrap();
        let bytes = query("example.com").to_vec().unwrap();
        let first = Message::from_vec(&resolver.resolve(&bytes, peer).await.unwrap()).unwrap();
        assert_eq!(first.metadata.response_code, ResponseCode::NoError);
        assert_eq!(first.metadata.id, 4123);
        assert_eq!(count.load(Ordering::Relaxed), 1);
        {
            let mut cache = resolver.cache.lock().await;
            for (_, entry) in cache.iter_mut() {
                entry.inserted = Instant::now() - Duration::from_secs(10);
            }
        }
        let second = Message::from_vec(&resolver.resolve(&bytes, peer).await.unwrap()).unwrap();
        assert!(second.answers[0].ttl <= 110);
        assert_eq!(count.load(Ordering::Relaxed), 1);
        assert!(!rx.recv().await.unwrap().cached);
        assert!(rx.recv().await.unwrap().cached);
        let alias = Message::from_vec(
            &resolver
                .resolve(&query("alias.example").to_vec().unwrap(), peer)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(alias.metadata.response_code, ResponseCode::NXDomain);
        // New rules must also override an already cached positive answer.
        sqlx::query(
            "INSERT INTO rules(domain, action, created_at) VALUES ('example.com','block',0)",
        )
        .execute(&resolver.app.db)
        .await
        .unwrap();
        resolver.app.reload().await.unwrap();
        let blocked = Message::from_vec(&resolver.resolve(&bytes, peer).await.unwrap()).unwrap();
        assert_eq!(blocked.metadata.response_code, ResponseCode::NXDomain);
        task.abort();
        bad_task.abort();
    }
}
