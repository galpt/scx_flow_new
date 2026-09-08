/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Loopback dashboard for the flow scheduler. Serves the
 * embedded page and the live snapshot as JSON. Prefers
 * the loopback TCP port and falls back to a unix socket
 * when the sandbox blocks TCP. No auth is used. The
 * loopback address is the trust boundary.
 */
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use crossbeam::channel::Receiver;
use serde::Serialize;
use serde_json::json;
use serde_json::Value;
use tiny_http::Header;
use tiny_http::Response;
use tiny_http::Server;

use crate::stats::WebMetrics;

/* Loopback TCP port of the dashboard. */
const PORT: u16 = 50005;
/* Unix socket path used when TCP is blocked. */
const SOCK: &str = "/tmp/scx_flow.sock";
/* Poll bound of the snapshot channel. */
const POLL: Duration = Duration::from_millis(200);
/* JSON content type value. */
const JSON: &str = "application/json";
/* HTML content type value. */
const HTML: &str = "text/html";

/* Newest snapshot behind a lock for the handlers. */
struct WebState {
    metrics: WebMetrics,
}

/* JSON value of a serializable item. */
fn jv<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or_default()
}

/* JSON text of a value. Empty object on failure. */
fn jt(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or("{}".into())
}

/* Merged dashboard object for one snapshot. */
fn merged(snap: &WebMetrics) -> Value {
    json!({
        "stats": jv(&snap.stats),
        "per_cpu": jv(&snap.per_cpu),
        "mean_ns": jv(&snap.mean_ns),
    })
}

/*
 * Serve one unix client. Routes mirror the TCP server.
 * The root serves the page. The stats path serves JSON.
 * Unknown paths get a short not found reply.
 */
fn unix_client(
    mut stream: std::os::unix::net::UnixStream,
    state: &Arc<Mutex<WebState>>,
    html: &str,
) {
    let dup = match stream.try_clone() {
        Ok(v) => v,
        Err(_) => return,
    };
    let mut rd = BufReader::new(dup);
    let mut line = String::new();
    if rd.read_line(&mut line).is_err() {
        return;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let path = parts[1];
    let snap = match state.lock() {
        Ok(v) => v.metrics.clone(),
        Err(_) => return,
    };
    let (body, ctype) = match path {
        "/" => (html.as_bytes().to_vec(), HTML),
        "/api/stats" => {
            let txt = jt(&merged(&snap));
            (txt.into_bytes(), JSON)
        }
        _ => {
            let _ = write!(
                stream,
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
            );
            return;
        }
    };
    let len = body.len();
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n",
        ctype, len
    );
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

/*
 * Start the dashboard thread. Consumes snapshots and
 * exits when the shutdown flag is set or the channel
 * closes.
 */
pub fn start(rx: Receiver<WebMetrics>, shutdown: Arc<AtomicBool>) {
    log::info!("web thread started");
    let html = include_str!("../ui/index.html").to_string();
    let state = Arc::new(Mutex::new(WebState {
        metrics: WebMetrics::default(),
    }));
    let keep = state.clone();
    let done = shutdown.clone();
    std::thread::spawn(move || {
        while !done.load(Ordering::Relaxed) {
            match rx.recv_timeout(POLL) {
                Ok(m) => {
                    if let Ok(mut s) = keep.lock() {
                        s.metrics = m;
                    }
                }
                Err(crossbeam::channel::RecvTimeoutError::Timeout) => {}
                Err(_) => break,
            }
        }
    });
    let unix_html = html.clone();
    let mut server: Option<Server> = None;
    let mut addr = String::new();
    if let Ok(s) = Server::http(format!("[::1]:{PORT}")) {
        addr = format!("[::1]:{PORT}");
        server = Some(s);
    }
    if server.is_none() {
        if let Ok(s) = Server::http(format!("127.0.0.1:{PORT}")) {
            addr = format!("127.0.0.1:{PORT}");
            server = Some(s);
        }
    }
    if let Some(server) = server {
        log::info!("web on port {addr}");
        let nocache = Header::from_bytes("Cache-Control", "no-store").unwrap();
        let htype = Header::from_bytes("Content-Type", HTML).unwrap();
        let jtype = Header::from_bytes("Content-Type", JSON).unwrap();
        while !shutdown.load(Ordering::Relaxed) {
            let got = server.recv_timeout(Duration::from_millis(200));
            let req = match got {
                Ok(Some(v)) => v,
                _ => continue,
            };
            let snap = match state.lock() {
                Ok(v) => v.metrics.clone(),
                Err(_) => continue,
            };
            match req.url() {
                "/" => {
                    let resp = Response::from_string(&html);
                    let resp = resp.with_header(htype.clone());
                    let resp = resp.with_header(nocache.clone());
                    let _ = req.respond(resp);
                }
                "/api/stats" => {
                    let txt = jt(&merged(&snap));
                    let resp = Response::from_string(txt);
                    let resp = resp.with_header(jtype.clone());
                    let resp = resp.with_header(nocache.clone());
                    let _ = req.respond(resp);
                }
                _ => {
                    let _ = req.respond(Response::empty(404));
                }
            }
        }
    } else {
        log::warn!("web TCP blocked, unix fallback");
        if let Ok(m) = std::fs::symlink_metadata(SOCK) {
            if m.file_type().is_socket() {
                let _ = std::fs::remove_file(SOCK);
            }
        }
        let lis = match UnixListener::bind(SOCK) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("unix bind failed: {e}");
                return;
            }
        };
        let mode = PermissionsExt::from_mode(0o600);
        if std::fs::set_permissions(SOCK, mode).is_err() {
            log::warn!("socket mode failed");
        }
        log::info!("web on unix socket");
        if lis.set_nonblocking(true).is_err() {
            log::warn!("nonblock failed");
            return;
        }
        while !shutdown.load(Ordering::Relaxed) {
            match lis.accept() {
                Ok((s, _)) => {
                    let st = state.clone();
                    let h = unix_html.clone();
                    std::thread::spawn(move || unix_client(s, &st, &h));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    log::warn!("accept failed: {e}");
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
    log::info!("web stopped");
}
