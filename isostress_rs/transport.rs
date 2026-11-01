// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 isostress Suite maintainers

//! Transport and session runner (Master Guide Appendix H.3 timers / H.6 cleanup semantics).
//!
//! Provides:
//! - Two runner entry points, listen (responder) and connect (initiator), with connection retry and a self-connection warning;
//! - Interactive chat session: receive thread + heartbeat thread + main-thread send loop;
//! - Idempotent shutdown (Appendix H.6): the exit paths of the three threads
//!   converge so the socket is closed exactly once and the session key is
//!   wiped exactly once - otherwise long runs accumulate half-open sockets (FD leaks) and residual keys.
//!
//! Hardening over the Python reference implementation:
//! - `TCP_NODELAY` is enabled on all connections, eliminating the 40-200 ms
//!   interactive latency caused by Nagle + delayed ACK;
//! - optional connection rate limiting on the listener (`--rate-limit`, token bucket, 0 = off);
//! - `SO_REUSEADDR` is not set on Windows (avoids grabbing ports
//!   already bound by others); enabled on Unix only to reuse TIME_WAIT.

use std::fmt;
use std::io::{BufRead, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::errors::{Error, Result};
use crate::frames::force_close_socket;
use crate::handshake::{HandshakePeer, Role, DATA_TIMEOUT, HANDSHAKE_TIMEOUT, SILENT_DROP_HOLD};
use crate::params::{Params, TIME_WINDOW};
use crate::session::SecureSession;

pub const DEFAULT_PORT: u16 = 37291;
pub const DEFAULT_HOST_LISTEN: &str = "0.0.0.0";
pub const DEFAULT_HOST_CONNECT: &str = "127.0.0.1";
pub const DEFAULT_CONNECT_RETRY_COUNT: u32 = 3;
pub const DEFAULT_CONNECT_RETRY_INTERVAL: f64 = 5.0;
/// Empty-payload heartbeat interval (Appendix G.5: baseline traffic + half-open detection)
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Session configuration (the normalized product of the CLI).
///
/// No `Clone`: every consumer takes `&SessionConfig` and clones only the
/// fields it needs, so no unnoticed PSK copies accumulate. The hand-written
/// `Debug` never prints the PSK.
pub struct SessionConfig {
    pub psk: Vec<u8>,
    pub params: Params,
    pub time_window: u64,
    pub padding: Option<(usize, usize)>,
    pub jitter: f64,
    pub silent_hold: Duration,
    pub handshake_timeout: Duration,
    pub retry_count: u32,
    pub retry_interval: f64,
    /// Connection rate limit (connections per second; 0 = off)
    pub rate_limit: u32,
    /// Read the input for sending (false = receive only)
    pub read_stdin: bool,
}

impl fmt::Debug for SessionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionConfig")
            .field("psk_len", &self.psk.len())
            .field("params", &self.params)
            .field("time_window", &self.time_window)
            .field("padding", &self.padding)
            .field("jitter", &self.jitter)
            .field("silent_hold", &self.silent_hold)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("retry_count", &self.retry_count)
            .field("retry_interval", &self.retry_interval)
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            psk: Vec::new(),
            params: Params::new().expect("default params are valid"),
            time_window: TIME_WINDOW,
            padding: None,
            jitter: 0.0,
            silent_hold: SILENT_DROP_HOLD,
            handshake_timeout: HANDSHAKE_TIMEOUT,
            retry_count: DEFAULT_CONNECT_RETRY_COUNT,
            retry_interval: DEFAULT_CONNECT_RETRY_INTERVAL,
            rate_limit: 0,
            read_stdin: true,
        }
    }
}

fn set_socket_options(sock: &TcpStream) {
    // interactive messages no longer stall 40-200 ms under Nagle + delayed ACK
    let _ = sock.set_nodelay(true);
}

/// Connection rate limiter (first gate against unauthenticated computational DoS).
/// Simple token bucket: capacity = rate, refilled with rate tokens per second.
struct RateLimiter {
    rate: f64,
    tokens: Mutex<(f64, Instant)>,
}

impl RateLimiter {
    fn new(rate: u32) -> Self {
        RateLimiter {
            rate: rate as f64,
            tokens: Mutex::new((rate as f64, Instant::now())),
        }
    }

    fn allow(&self) -> bool {
        let mut st = self.tokens.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(st.1).as_secs_f64();
        st.0 = (st.0 + elapsed * self.rate).min(self.rate);
        st.1 = now;
        if st.0 >= 1.0 {
            st.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

// =============================================================================
// Interactive chat session
// =============================================================================

/// Three-thread interactive session: receive / heartbeat / send. shutdown is idempotent (Appendix H.6).
pub struct ChatSession {
    session: Arc<SecureSession>,
    stream: TcpStream,
    running: Arc<AtomicBool>,
    print_lock: Arc<Mutex<()>>,
    read_stdin: bool,
}

struct ChatHandle {
    session: Arc<SecureSession>,
    stream: TcpStream,
    running: Arc<AtomicBool>,
    print_lock: Arc<Mutex<()>>,
    read_stdin: bool,
}

impl ChatHandle {
    /// Diagnostics go to stderr; peer text and the prompt stay on stdout, so a
    /// piped session does not mix local notices into the data stream.
    fn eprint(&self, line: &str) {
        let _g = self.print_lock.lock().unwrap();
        eprintln!("{line}");
        let _ = std::io::stderr().flush();
    }

    /// Idempotent shutdown: the socket is closed exactly once, the key wiped exactly once.
    fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = self.stream.shutdown(Shutdown::Both);
        self.session.wipe();
    }
}

impl ChatSession {
    /// Two-argument constructor kept from 1.0.0; the session reads stdin.
    pub fn new(session: SecureSession, stream: TcpStream) -> Self {
        Self::with_input(session, stream, true)
    }

    /// Constructor with explicit control over whether stdin is read.
    pub fn with_input(session: SecureSession, stream: TcpStream, read_stdin: bool) -> Self {
        set_socket_options(&stream);
        ChatSession {
            session: Arc::new(session),
            stream,
            running: Arc::new(AtomicBool::new(true)),
            print_lock: Arc::new(Mutex::new(())),
            read_stdin,
        }
    }

    /// Starts the receive/heartbeat threads and blocks in the send loop (main-thread stdin).
    pub fn start(self) {
        let ChatSession {
            session,
            stream,
            running,
            print_lock,
            read_stdin,
        } = self;

        let recv_handle = ChatHandle {
            session: session.clone(),
            stream: stream.try_clone().expect("clone stream for recv thread"),
            running: running.clone(),
            print_lock: print_lock.clone(),
            read_stdin,
        };
        let hb_handle = ChatHandle {
            session: session.clone(),
            stream: stream
                .try_clone()
                .expect("clone stream for heartbeat thread"),
            running: running.clone(),
            print_lock: print_lock.clone(),
            read_stdin,
        };

        let recv_thread = std::thread::Builder::new()
            .name("isostress-recv".into())
            .spawn(move || recv_loop(&recv_handle))
            .expect("spawn recv thread");
        let hb_thread = std::thread::Builder::new()
            .name("isostress-heartbeat".into())
            .spawn(move || heartbeat_loop(&hb_handle))
            .expect("spawn heartbeat thread");

        // Main-thread send loop
        let main_handle = ChatHandle {
            session,
            stream,
            running,
            print_lock,
            read_stdin,
        };
        if read_stdin {
            send_loop(&main_handle);
        } else {
            main_handle.eprint("[Input disabled] receiving only");
        }

        recv_thread.join().ok();
        hb_thread.join().ok();
        // Converge idempotently once the main loop exits
        main_handle.shutdown();
    }
}

fn recv_loop(h: &ChatHandle) {
    let mut sock = match h.stream.try_clone() {
        Ok(s) => s,
        Err(_) => {
            h.shutdown();
            return;
        }
    };
    while h.running.load(Ordering::SeqCst) {
        match h.session.recv_packet(&mut sock) {
            Ok(data) => {
                if data.is_empty() {
                    // A heartbeat carries no text; an out-of-window packet is
                    // dropped on purpose, and the reason says which one it was
                    if let Some(reason) = h.session.last_recv_drop() {
                        h.eprint(&format!("[Dropped] {reason}"));
                    }
                    continue;
                }
                let text = String::from_utf8_lossy(&data);
                let _g = h.print_lock.lock().unwrap();
                println!("[Peer] {text}");
                if h.read_stdin {
                    print!("> ");
                    let _ = std::io::stdout().flush();
                }
            }
            Err(Error::Timeout(e)) => {
                h.eprint(&format!("[Timeout] {e}"));
                break;
            }
            Err(Error::Io(_)) => break, // Connection closed/reset: wind down silently
            Err(e) => {
                h.eprint(&format!("[Security error] {e}"));
                break;
            }
        }
    }
    h.shutdown();
}

fn heartbeat_loop(h: &ChatHandle) {
    let mut sock = match h.stream.try_clone() {
        Ok(s) => s,
        Err(_) => {
            h.shutdown();
            return;
        }
    };
    while h.running.load(Ordering::SeqCst) {
        // Interruptible sleep: poll the running flag in 100 ms steps so that
        // the thread exits within 0.1 s after shutdown (avoids join blocking for a full heartbeat period)
        let mut waited = Duration::ZERO;
        while waited < HEARTBEAT_INTERVAL && h.running.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
            waited += Duration::from_millis(100);
        }
        if !h.running.load(Ordering::SeqCst) {
            break;
        }
        // Application-layer heartbeat: detect half-open connections + take part in ratchet rotation (Appendix G.5)
        if let Err(_e) = h.session.send_packet(&mut sock, b"") {
            if h.running.load(Ordering::SeqCst) {
                h.eprint("[Heartbeat failed] connection may have been disconnected");
            }
            break;
        }
    }
    h.shutdown();
}

fn send_loop(h: &ChatHandle) {
    let mut sock = match h.stream.try_clone() {
        Ok(s) => s,
        Err(_) => {
            h.shutdown();
            return;
        }
    };
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    while h.running.load(Ordering::SeqCst) {
        let line = match lines.next() {
            Some(Ok(l)) => l,
            None => {
                // The input ended: the sending stops, the receiving goes on
                h.eprint("[Input closed] sending stopped; receiving continues");
                break;
            }
            Some(Err(e)) => {
                h.eprint(&format!("[Input error] {e}"));
                break;
            }
        };
        if line.is_empty() {
            continue;
        }
        let lower = line.trim().to_ascii_lowercase();
        if lower == "/quit" || lower == "/exit" || lower == "/q" {
            break;
        }
        match h.session.send_packet(&mut sock, line.as_bytes()) {
            Ok(()) => {}
            Err(e) => {
                h.eprint(&format!("[Send failed] {e}"));
                break;
            }
        }
    }
}

// =============================================================================
// Listen / connect runner
// =============================================================================

fn print_params(cfg: &SessionConfig) {
    println!(
        "    Params: random_len={}, rate={}, window={}, time_window={}",
        cfg.params.random_len, cfg.params.random_rate, cfg.params.window, cfg.time_window
    );
}

/// Listen mode (responder). Strictly fail silent, then close the connection (H.3: close on hold exhaustion).
pub fn run_listen(cfg: &SessionConfig, host: &str, port: u16) -> Result<()> {
    println!("\n[+] Listening on {host}:{port} ...");
    print_params(cfg);
    println!("    Waiting for peer connection... (Ctrl+C to abort)");

    // no SO_REUSEADDR on Windows (exclusive binding by default, never steal others' ports);
    // enable it on Unix to reuse TIME_WAIT, for fast restarts.
    #[cfg(unix)]
    let listener = {
        use socket2::{Domain, Protocol, Socket, Type};
        let addr = format!("{host}:{port}");
        let addr: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| Error::param(format!("Invalid listen address: {e}")))?;
        let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))
            .map_err(Error::Io)?;
        let _ = socket.set_reuse_address(true);
        socket.bind(&addr.into()).map_err(Error::Io)?;
        socket.listen(1).map_err(Error::Io)?;
        TcpListener::from(socket)
    };
    #[cfg(not(unix))]
    let listener = TcpListener::bind((host, port)).map_err(Error::Io)?;

    let limiter = if cfg.rate_limit > 0 {
        Some(RateLimiter::new(cfg.rate_limit))
    } else {
        None
    };

    let (mut conn, addr) = match listener.accept() {
        Ok(v) => v,
        Err(e) => {
            println!("\n[!] Failed to accept connection: {e}");
            return Err(Error::Io(e));
        }
    };
    drop(listener);

    // connection rate limiting (off = unlimited, kept consistent with the reference CLI behavior)
    if let Some(l) = &limiter {
        if !l.allow() {
            // Over the limit: close immediately and silently (no bytes sent)
            force_close_socket(&conn);
            println!("[!] Connection rate limit exceeded, silently closed: {addr}");
            return Ok(());
        }
    }

    println!("[+] Connection from {addr}");
    set_socket_options(&conn);
    let mut peer = match HandshakePeer::new(
        cfg.psk.clone(),
        cfg.params.clone(),
        Role::Responder,
        cfg.padding,
        cfg.jitter,
        cfg.time_window,
        cfg.silent_hold,
        cfg.handshake_timeout,
    ) {
        Ok(p) => p,
        Err(e) => {
            println!("\n[!] Failed to build handshake peer: {e}");
            force_close_socket(&conn);
            return Err(e);
        }
    };

    match peer.perform_handshake(&mut conn) {
        Ok(material) => {
            println!("[+] Handshake complete, secure channel established.");
            println!("    Type a message and press Enter to send; /quit or Ctrl+C to exit\n");
            let session = SecureSession::new(material);
            ChatSession::with_input(session, conn, cfg.read_stdin).start();
            Ok(())
        }
        Err(Error::SilentDrop(e)) => {
            // Silent drop hold exhausted (or the peer closed first): closing now leaks no information (H.3)
            println!("\n[!] {e}");
            force_close_socket(&conn);
            Ok(())
        }
        Err(Error::Io(e)) => {
            println!("\n[!] Connection error: {e}");
            force_close_socket(&conn);
            Err(Error::Io(e))
        }
        Err(e) => {
            println!("\n[!] Handshake failed: {e}");
            println!("    Possible causes: PSK mismatch / parameter mismatch / network tampering");
            force_close_socket(&conn);
            Err(e)
        }
    }
}

/// Check whether the target address is local (covers localhost aliases and loopback).
fn is_self_connection(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "0.0.0.0" | "::1" | "localhost")
}

/// Connect mode (initiator), with retries (Appendix B: 3 attempts by default, 5 s apart).
pub fn run_connect(cfg: &SessionConfig, host: &str, port: u16) -> Result<()> {
    println!("\n[+] Connecting to {host}:{port} ...");
    print_params(cfg);

    if is_self_connection(host) {
        println!("  [!] Warning: target address {host} is a local address.");
        println!("    If no isostress in listen mode is running on this machine, the connection will fail.\n");
    }

    let addr_str = format!("{host}:{port}");
    let addr: std::net::SocketAddr = addr_str
        .parse()
        .map_err(|e| Error::param(format!("Invalid target address: {e}")))?;

    for attempt in 1..=cfg.retry_count {
        if attempt > 1 {
            println!("    Attempt {attempt}/{0} connecting...", cfg.retry_count);
        }
        let mut conn = match TcpStream::connect_timeout(&addr, cfg.handshake_timeout) {
            Ok(c) => c,
            Err(e) => {
                if attempt < cfg.retry_count {
                    println!(
                        "    Connection failed: {e}, retrying in {0} s...",
                        cfg.retry_interval
                    );
                    std::thread::sleep(Duration::from_secs_f64(cfg.retry_interval));
                    continue;
                }
                println!(
                    "\n[!] Connection failed, max retries ({0}) reached",
                    cfg.retry_count
                );
                println!("    Last error: {e}");
                return Err(Error::Io(e));
            }
        };
        set_socket_options(&conn);
        // Use 15 s for the handshake, restore 60 s for the data phase (the 30 s heartbeat must keep up)
        let _ = conn.set_read_timeout(Some(DATA_TIMEOUT));
        let _ = conn.set_write_timeout(Some(DATA_TIMEOUT));

        let mut peer = match HandshakePeer::new(
            cfg.psk.clone(),
            cfg.params.clone(),
            Role::Initiator,
            cfg.padding,
            cfg.jitter,
            cfg.time_window,
            cfg.silent_hold,
            cfg.handshake_timeout,
        ) {
            Ok(p) => p,
            Err(e) => {
                println!("\n[!] Failed to build handshake peer: {e}");
                force_close_socket(&conn);
                return Err(e);
            }
        };

        match peer.perform_handshake(&mut conn) {
            Ok(material) => {
                println!("[+] Handshake complete, secure channel established.");
                println!("    Type a message and press Enter to send; /quit or Ctrl+C to exit\n");
                let session = SecureSession::new(material);
                ChatSession::with_input(session, conn, cfg.read_stdin).start();
                return Ok(());
            }
            Err(Error::Io(e)) => {
                println!("\n[!] Connection error: {e}");
                force_close_socket(&conn);
                return Err(Error::Io(e));
            }
            Err(e) => {
                println!("\n[!] Handshake failed: {e}");
                println!(
                    "    Possible causes: PSK mismatch / parameter mismatch / network tampering"
                );
                force_close_socket(&conn);
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Session runner entry point (invoked by the CLI).
pub fn run_session(role: Role, cfg: &SessionConfig, host: &str, port: u16) -> Result<()> {
    match role {
        Role::Responder => run_listen(cfg, host, port),
        Role::Initiator => run_connect(cfg, host, port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SessionConfig carries the PSK. Its Debug output must show the key
    /// length, never the key bytes; without this guard a future derive
    /// or field addition would leak the PSK into one `{:?}` print.
    #[test]
    fn debug_output_contains_no_psk() {
        let cfg = SessionConfig {
            psk: vec![0x5A; 32],
            ..SessionConfig::default()
        };
        let out = format!("{cfg:?}");
        assert!(
            !out.contains("5a5a") && !out.contains("5A5A"),
            "PSK leaked via Debug: {out}"
        );
        assert!(out.contains("psk_len: 32"), "length stays visible: {out}");
    }

    #[test]
    fn the_session_reads_the_input_by_default() {
        assert!(SessionConfig::default().read_stdin);
    }
}
