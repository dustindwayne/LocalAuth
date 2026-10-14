use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use clap::Parser;
use localauth_home::{Store, MAX_BLOB};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "data")]
    data: PathBuf,
    #[arg(long, default_value = "7443")]
    port: u16,
    #[arg(long, default_value = "7444")]
    admin_port: u16,
    /// Explicitly permit clients outside private LAN address ranges.
    #[arg(long)]
    remote: bool,
    #[arg(long, default_value = "0.0.0.0")]
    bind_address: std::net::IpAddr,
    /// Skip mDNS advertisement (e.g. public-only server).
    #[arg(long)]
    no_discovery: bool,
}
#[derive(Clone)]
struct App {
    store: Arc<Store>,
    admin: String,
    pin: String,
    url: String,
    remote: bool,
    admin_port: u16,
    rates: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
}
type ApiResult = Result<Response, StatusCode>;
fn field<'a>(h: &'a HeaderMap, name: &str) -> Result<&'a str, StatusCode> {
    h.get(name)
        .and_then(|x| x.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)
}
fn authorize(
    s: &App,
    h: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<String, StatusCode> {
    let id = field(h, "x-device")?;
    if id.len() > 100 {
        return Err(StatusCode::UNAUTHORIZED);
    }
    s.store
        .verify(
            id,
            field(h, "x-challenge")?,
            field(h, "x-signature")?,
            method,
            path,
            body,
        )
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(id.to_owned())
}
fn admin(s: &App, h: &HeaderMap) -> Result<(), StatusCode> {
    let host = field(h, "host")?;
    if host != format!("127.0.0.1:{}", s.admin_port)
        && host != format!("localhost:{}", s.admin_port)
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let auth = field(h, "authorization")?
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !bool::from(auth.as_bytes().ct_eq(s.admin.as_bytes())) {
        return Err(StatusCode::UNAUTHORIZED);
    };
    Ok(())
}
async fn secure(
    State(s): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let local = match peer.ip() {
        std::net::IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
        std::net::IpAddr::V6(v) => {
            v.is_loopback()
                || v.is_unique_local()
                || v.is_unicast_link_local()
                || v.to_ipv4_mapped()
                    .is_some_and(|v| v.is_private() || v.is_loopback())
        }
    };
    if !local && !s.remote {
        return StatusCode::FORBIDDEN.into_response();
    }
    {
        let mut rates = s.rates.lock().unwrap();
        rates.retain(|_, (t, _)| t.elapsed() < Duration::from_secs(60));
        if rates.len() >= 4096 && !rates.contains_key(&peer.ip().to_string()) {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        };
        let entry = rates
            .entry(peer.ip().to_string())
            .or_insert((Instant::now(), 0));
        entry.1 += 1;
        if entry.1 > 120 {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
    }
    let mut response = next.run(req).await;
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
}
#[derive(Deserialize)]
struct Pair {
    ticket: String,
    public_key: String,
    label: String,
    proof: String,
}
async fn pair(State(s): State<App>, Json(p): Json<Pair>) -> ApiResult {
    let d = s
        .store
        .pair_signed(&s.pin, &p.ticket, &p.public_key, &p.label, &p.proof)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(Json(json!({"device":d.id})).into_response())
}
async fn challenge(State(s): State<App>, Path(id): Path<String>, h: HeaderMap) -> ApiResult {
    let timestamp_text = field(&h, "x-client-time")?;
    let timestamp: u64 = timestamp_text
        .parse()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if timestamp.to_string() != timestamp_text {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let n = s
        .store
        .challenge_signed(
            &s.pin,
            &id,
            field(&h, "x-client-nonce")?,
            timestamp,
            field(&h, "x-signature")?,
        )
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(Json(json!({"protocol":2,"challenge":n,"expires_in":60})).into_response())
}
async fn upload(State(s): State<App>, h: HeaderMap, body: Bytes) -> ApiResult {
    let id = authorize(&s, &h, "POST", "/v1/backup", &body)?;
    let id = s
        .store
        .save(&id, &body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(json!({"version":id})).into_response())
}
async fn download(State(s): State<App>, h: HeaderMap) -> ApiResult {
    let id = authorize(&s, &h, "GET", "/v1/backup", b"")?;
    let body = s.store.latest(&id).map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(([("content-type", "application/octet-stream")], body).into_response())
}
async fn health() -> Json<serde_json::Value> {
    Json(json!({"protocol":2,"name":"LocalAuth Home"}))
}
async fn dashboard() -> Response {
    let mut r = Html(include_str!("../web/index.html")).into_response();
    r.headers_mut().insert("content-security-policy",HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"));
    r.headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    r.headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    r
}
async fn js() -> impl IntoResponse {
    (
        [
            ("content-type", "text/javascript"),
            ("cache-control", "no-store"),
        ],
        include_str!("../web/app.js"),
    )
}
async fn css() -> impl IntoResponse {
    (
        [("content-type", "text/css")],
        include_str!("../web/style.css"),
    )
}
async fn status(State(s): State<App>, h: HeaderMap) -> ApiResult {
    admin(&s, &h)?;
    let devices = s
        .store
        .devices()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut out = Vec::new();
    for d in devices {
        let snapshots = s
            .store
            .snapshots(&d.id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        out.push(json!({"id":d.id,"label":d.label,"paired":d.paired,"revoked":d.revoked,"backups":snapshots}));
    }
    Ok(Json(json!({"url":s.url,"pin":s.pin,"remote":s.remote,"devices":out})).into_response())
}
#[derive(Deserialize)]
struct PairOffer {
    url: String,
}
async fn offer(State(s): State<App>, h: HeaderMap, Json(p): Json<PairOffer>) -> ApiResult {
    admin(&s, &h)?;
    let url = url::Url::parse(&p.url).map_err(|_| StatusCode::BAD_REQUEST)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let ticket = s
        .store
        .ticket()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let code = json!({"v":2,"url":url.as_str().trim_end_matches('/'),"pin":s.pin,"ticket":ticket});
    let pairing = format!(
        "localauth-pair:{}",
        B64.encode(serde_json::to_vec(&code).unwrap())
    );
    let qr = qrcode::QrCode::new(pairing.as_bytes())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(300, 300)
        .build();
    Ok(
        Json(json!({"pairing":pairing,"qr":B64.encode(qr.as_bytes()),"expires_in":300}))
            .into_response(),
    )
}
async fn revoke(State(s): State<App>, h: HeaderMap, Path(id): Path<String>) -> ApiResult {
    admin(&s, &h)?;
    s.store
        .revoke(&id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
async fn export(State(s): State<App>, h: HeaderMap, Path(id): Path<String>) -> ApiResult {
    admin(&s, &h)?;
    let b = s.store.latest(&id).map_err(|_| StatusCode::NOT_FOUND)?;
    Ok((
        [
            ("content-type", "application/octet-stream"),
            (
                "content-disposition",
                "attachment; filename=localauth-backup.lab",
            ),
        ],
        b,
    )
        .into_response())
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    std::fs::create_dir_all(&args.data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&args.data, std::fs::Permissions::from_mode(0o700))?;
    }
    let cert_path = args.data.join("server.pem");
    let key_path = args.data.join("server-key.pem");
    let ip = local_ip_address::local_ip().unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    if !cert_path.exists() && !key_path.exists() {
        let generated = rcgen::generate_simple_self_signed(vec![
            "localhost".into(),
            "localauth-home.local".into(),
            ip.to_string(),
        ])?;
        std::fs::write(&key_path, generated.signing_key.serialize_pem())?;
        std::fs::write(&cert_path, generated.cert.pem())?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    let pem = std::fs::read(&cert_path)?;
    let der = rustls_pemfile::certs(&mut pem.as_slice())
        .next()
        .ok_or_else(|| anyhow::anyhow!("Missing TLS certificate"))??;
    let pin = localauth_home::hash(der.as_ref());
    let admin_token = localauth_home::random();
    let s = App {
        store: Store::open(&args.data.join("backups.redb"))?,
        admin: admin_token.clone(),
        pin,
        url: format!("https://{ip}:{}", args.port),
        remote: args.remote,
        admin_port: args.admin_port,
        rates: Arc::new(Mutex::new(HashMap::new())),
    };
    let mdns = if !args.no_discovery {
        let daemon = mdns_sd::ServiceDaemon::new()?;
        let service = mdns_sd::ServiceInfo::new(
            "_localauth._tcp.local.",
            "LocalAuth Home",
            "localauth-home.local.",
            "",
            args.port,
            None,
        )?
        .enable_addr_auto();
        daemon.register(service)?;
        Some(daemon)
    } else {
        None
    };
    let api = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/pair", post(pair).layer(DefaultBodyLimit::max(4096)))
        .route("/v1/challenge/{id}", get(challenge))
        .route("/v1/backup", post(upload).get(download))
        .layer(DefaultBodyLimit::max(MAX_BLOB))
        .layer(middleware::from_fn_with_state(s.clone(), secure))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(20),
        ))
        .with_state(s.clone());
    let panel = Router::new()
        .route("/", get(dashboard))
        .route("/app.js", get(js))
        .route("/style.css", get(css))
        .route("/admin/status", get(status))
        .route("/admin/offer", post(offer))
        .route("/admin/revoke/{id}", post(revoke))
        .route("/admin/export/{id}", get(export))
        .layer(DefaultBodyLimit::max(4096))
        .with_state(s);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", args.admin_port)).await?;
    println!(
        "Local dashboard: http://127.0.0.1:{}/#{}",
        args.admin_port, admin_token
    );
    println!(
        "Backup HTTPS port {}. Remote clients: {}. Keep the data directory private.",
        args.port, args.remote
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, panel).await;
    });
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("TLS crypto provider unavailable"))?;
    let tls = RustlsConfig::from_pem_file(cert_path, key_path).await?;
    let handle: axum_server::Handle<SocketAddr> = axum_server::Handle::new();
    let quit = handle.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        quit.graceful_shutdown(Some(Duration::from_secs(5)));
    });
    axum_server::bind_rustls(SocketAddr::new(args.bind_address, args.port), tls)
        .handle(handle)
        .serve(api.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    if let Some(daemon) = mdns {
        let _ = daemon.shutdown();
    }
    Ok(())
}
