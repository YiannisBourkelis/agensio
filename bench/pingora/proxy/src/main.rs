// The Pingora side of bench/pingora/run.sh: a reverse proxy as Pingora's own examples write one
// (pingora-proxy's load_balancer.rs and multi_lb.rs), with nothing added but what the comparison
// needs. One service, a plain listener and a TLS one (HTTP/2 offered), every request forwarded to
// an HTTP/1.1 origin over a kept connection from Pingora's shared pool.
//
// What it forwards is what agensio forwards by default, so the origin parses the same request
// from both: Host as the client sent it, X-Forwarded-For, X-Forwarded-Proto and X-Real-IP.
//
// Settings, all from the environment so the run script states them in one place:
//   PB_LISTEN      plain listener, e.g. 127.0.0.1:8096
//   PB_LISTEN_TLS  TLS listener, e.g. 127.0.0.1:8496 (needs PB_CERT and PB_KEY)
//   PB_THREADS     threads of the proxy service (Pingora's `threads`), default 1
//   PB_UPSTREAM    the origin, default 127.0.0.1:9100
//   PB_ORIGINS     N > 0: the origin is chosen by Host. "o<K>.test" goes to the K-th of N
//                  addresses, 127.1.<K / 250>.<K % 250 + 1> on PB_UPSTREAM's port
//   PB_POOL        upstream_keepalive_pool_size: idle connections kept to origins, all threads
//                  together. Pingora's default is 128; the run script sets what the row needs.
use async_trait::async_trait;
use pingora::http::RequestHeader;
use pingora::prelude::*;
use pingora::server::configuration::ServerConf;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

struct Proxy {
    upstream: SocketAddr,
    origins: usize,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

impl Proxy {
    // "o<K>.test[:port]" -> the K-th origin's address; anything else, the first.
    fn origin_for(&self, host: &[u8]) -> SocketAddr {
        let mut k: usize = 0;
        if host.first() == Some(&b'o') {
            for &c in &host[1..] {
                if !c.is_ascii_digit() {
                    break;
                }
                k = k * 10 + (c - b'0') as usize;
            }
        }
        let k = k % self.origins;
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 1, (k / 250) as u8, (k % 250 + 1) as u8)),
            self.upstream.port(),
        )
    }
}

#[async_trait]
impl ProxyHttp for Proxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(&self, session: &mut Session, _ctx: &mut ()) -> Result<Box<HttpPeer>> {
        let addr = if self.origins == 0 {
            self.upstream
        } else {
            // HTTP/1 carries the name in Host, HTTP/2 in :authority (the URI's authority).
            let req = session.req_header();
            match req.headers.get("host") {
                Some(h) => self.origin_for(h.as_bytes()),
                None => self.origin_for(req.uri.authority().map(|a| a.as_str().as_bytes()).unwrap_or(b"")),
            }
        };
        Ok(Box::new(HttpPeer::new(addr, false, String::new())))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        let tls = session.digest().map(|d| d.ssl_digest.is_some()).unwrap_or(false);
        upstream_request.insert_header("X-Forwarded-Proto", if tls { "https" } else { "http" })?;
        if let Some(ip) = session.client_addr().and_then(|a| a.as_inet()).map(|a| a.ip().to_string()) {
            upstream_request.insert_header("X-Forwarded-For", ip.as_str())?;
            upstream_request.insert_header("X-Real-IP", ip.as_str())?;
        }
        Ok(())
    }
}

fn main() {
    let threads: usize = env("PB_THREADS").and_then(|v| v.parse().ok()).unwrap_or(1);
    let mut conf = ServerConf::default();
    conf.threads = threads;
    if let Some(pool) = env("PB_POOL").and_then(|v| v.parse().ok()) {
        conf.upstream_keepalive_pool_size = pool;
    }
    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    let upstream: SocketAddr = env("PB_UPSTREAM")
        .unwrap_or_else(|| "127.0.0.1:9100".to_string())
        .parse()
        .expect("PB_UPSTREAM is ip:port");
    let origins: usize = env("PB_ORIGINS").and_then(|v| v.parse().ok()).unwrap_or(0);

    let mut proxy = http_proxy_service(&server.configuration, Proxy { upstream, origins });
    if let Some(listen) = env("PB_LISTEN") {
        proxy.add_tcp(&listen);
    }
    if let Some(listen) = env("PB_LISTEN_TLS") {
        let cert = env("PB_CERT").expect("PB_CERT");
        let key = env("PB_KEY").expect("PB_KEY");
        let mut tls = pingora::listeners::tls::TlsSettings::intermediate(&cert, &key).expect("certificate and key");
        tls.enable_h2();
        proxy.add_tls_with_settings(&listen, None, tls);
    }
    server.add_service(proxy);
    println!(
        "pingora {} proxy: {} thread(s), origin {}{}",
        env!("PINGORA_VERSION"),
        threads,
        upstream,
        if origins > 0 { format!(", {} origins by Host", origins) } else { String::new() }
    );
    server.run_forever();
}
