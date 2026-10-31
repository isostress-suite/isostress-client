// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 isostress Suite maintainers

//! Minimal command-line interface (command-line direct-connection subset plus base-platform subcommands; see the reference-client README).
//!
//! Design boundaries:
//! - `--role listen/connect` direct command-line connection and `--version`;
//! - `bench` subcommand: handshake / throughput / crypto-primitive benchmarks (the base platform's main capability);
//! - `pskgen` subcommand: generate a 256-bit high-entropy PSK (hex output, for the E.5 local dual-instance trial);
//! - PSK injection priority (README main parameters): --psk-file (recommended, 0600) > --psk-env > --psk
//!   (plaintext on the command line, visible in the process list; for temporary testing only).
//!
//! Hardening over the Python reference implementation (Master Guide):
//! - Untrusted values of `--psk-env`/`--psk` are **never** opened as file paths —
//!   even if they happen to be existing paths they are treated as literals; only `--psk-file` reads a file;
//! - Reading the PSK file strips the UTF-8 BOM;
//! - The POSIX permission warning runs only on Unix platforms (it would be a false positive on Windows).

use std::path::Path;
use std::sync::LazyLock;
use std::time::Duration;

use clap::{CommandFactory, Parser};
use zeroize::Zeroize;

use crate::crypto::{check_entropy, secure_random};
use crate::errors::{Error, Result};
use crate::params::{
    Params, AEAD_NAME, HASH_NAME, KEY_LEN, MAX_NONCE, MAX_PAD, RANDOM_LEN, RANDOM_RATE,
    TIME_WINDOW, WINDOW,
};
use crate::transport::{
    run_session, SessionConfig, DEFAULT_CONNECT_RETRY_COUNT, DEFAULT_CONNECT_RETRY_INTERVAL,
    DEFAULT_HOST_CONNECT, DEFAULT_HOST_LISTEN, DEFAULT_PORT,
};
use crate::version::{CODE_VERSION, FOLLOWS_DOC};

const PSK_LEN: usize = 32;
/// Publicly documented default PSK. It is not a credential:
/// the guide publishes it as forbidden, and every reference client must reject it.
const FORBIDDEN_DEFAULT_PSK: &str = "isostress-default-psk-32bytes-long!!";

/// 'static version/about strings required by clap.
static VERSION_LINE: LazyLock<String> = LazyLock::new(crate::version::format_version);
static ABOUT_LINE: LazyLock<String> = LazyLock::new(|| {
    format!("isostress Core {CODE_VERSION} (Rust) — Core Protocol (conforming to {FOLLOWS_DOC}) reference implementation")
});

// No Debug on Args: it carries the PSK from --psk / --psk-env, and a
// `{:?}` print would emit the secret.
#[derive(Parser)]
#[command(
    name = "isostress-rs",
    version = VERSION_LINE.as_str(),
    about = ABOUT_LINE.as_str(),
    after_help = "Examples:\n  # Listener (responder side)\n  isostress-rs --role listen --port 37291 --psk-file psk.txt\n  # Connector (initiator side)\n  isostress-rs --role connect --host <peer IP> --port 37291 --psk-file psk.txt\n  # PSK via environment variable\n  export ISOSTRESS_PSK=$(isostress-rs pskgen)\n  isostress-rs --role listen --port 37291 --psk-env\n\nPSK security recommendations:\n  1. Prefer --psk-file (permissions 0600)\n  2. Next --psk-env (environment variable ISOSTRESS_PSK)\n  3. Last --psk (insecure, visible in the process list)\n\nRunning with no arguments prints this usage. Extended modules (TCA/AORS/ocean mode etc.) are out of scope for this minimal distribution."
)]
pub struct Cli {
    /// Role: listen = listener (responder), connect = connector (initiator)
    #[arg(long)]
    role: Option<String>,
    /// Bind/target address
    #[arg(long)]
    host: Option<String>,
    /// Port number
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,
    /// PSK (64-char hex or Base64; not secure)
    #[arg(long)]
    psk: Option<String>,
    /// PSK file path (recommended)
    #[arg(long)]
    psk_file: Option<String>,
    /// Read from the ISOSTRESS_PSK environment variable
    #[arg(long, default_value_t = false)]
    psk_env: bool,
    /// Random-number length in bits (multiple of 8)
    #[arg(long, default_value_t = RANDOM_LEN)]
    random_len: u64,
    /// Generation rate (operations/second)
    #[arg(long, default_value_t = RANDOM_RATE)]
    random_rate: u64,
    /// Negotiation window in seconds; both sides must agree
    #[arg(long, default_value_t = WINDOW)]
    window: u64,
    /// Timestamp window in seconds (per peer)
    #[arg(long, default_value_t = TIME_WINDOW)]
    time_window: u64,
    /// Connection retry count
    #[arg(long, default_value_t = DEFAULT_CONNECT_RETRY_COUNT)]
    retry_count: u32,
    /// Retry interval in seconds
    #[arg(long, default_value_t = DEFAULT_CONNECT_RETRY_INTERVAL)]
    retry_interval: f64,
    /// Random padding lower bound in bytes (takes effect only when given together with --padding-max)
    #[arg(long)]
    padding_min: Option<usize>,
    /// Random padding upper bound in bytes (<= 2048)
    #[arg(long)]
    padding_max: Option<usize>,
    /// Send-timing jitter in seconds (0 = disabled)
    #[arg(long, default_value_t = 0.0)]
    jitter: f64,
    /// Strict silent-hold duration in seconds
    #[arg(long, default_value_t = 15.0)]
    silent_hold: f64,
    /// Connection rate limit (ops/second, 0 = disabled).
    #[arg(long, default_value_t = 0)]
    rate_limit: u32,
    #[command(subcommand)]
    command: Option<Command>,
}

impl Cli {
    /// Whether any PSK injection method was provided (README: at least one of the three).
    pub fn has_any_psk(&self) -> bool {
        self.psk_file.is_some() || self.psk_env || self.psk.is_some()
    }
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Generate a 256-bit high-entropy PSK (64-character hex output)
    Pskgen,
    /// Run the benchmarks (handshake / session throughput / crypto primitives)
    Bench {
        /// Handshake benchmark rounds
        #[arg(long, default_value_t = 30)]
        handshakes: usize,
        /// Throughput benchmark data size (MiB)
        #[arg(long, default_value_t = 16)]
        throughput_mib: usize,
        /// Base round count for the primitive benchmarks
        #[arg(long, default_value_t = 2000)]
        primitive_iters: usize,
    },
}

/// Generate a 256-bit high-entropy PSK.
pub fn generate_psk() -> Result<Vec<u8>> {
    secure_random(PSK_LEN)
}

/// Normalize user-supplied PSK input: exactly 32 bytes, as 64-char hex or standard Base64.
/// Reject public defaults and weak keys with too little entropy (Master Guide Appendix B: parameter reference).
pub fn normalize_psk(psk_input: &str) -> Result<Vec<u8>> {
    let s = psk_input.trim();
    if s.is_empty() || s == FORBIDDEN_DEFAULT_PSK {
        return Err(Error::param(
            "Reject weak / publicly known default PSK. Provide 64-character hex or standard Base64 of 32 bytes.",
        ));
    }
    let mut raw: Option<Vec<u8>> = None;
    if s.len() == 64 {
        if let Ok(v) = hex::decode(s) {
            raw = Some(v);
        }
    }
    if raw.is_none() {
        // Strict standard-Base64 decode (rejects whitespace and illegal characters, matching Python's validate=True)
        use base64::Engine;
        if let Ok(v) = base64::engine::general_purpose::STANDARD.decode(s.as_bytes()) {
            raw = Some(v);
        }
    }
    match raw {
        Some(r) if r.len() == PSK_LEN => {
            check_entropy(&r, 3.5)?;
            Ok(r)
        }
        _ => Err(Error::param(
            "PSK must be exactly 32 bytes of random data, encoded as 64-character hex or standard Base64.",
        )),
    }
}

/// Load the PSK from a file (warns when group/other-accessible on Unix; 0600 permissions recommended).
/// Strip the UTF-8 BOM (so files saved by Notepad work).
pub fn load_psk_from_file(path: &str) -> Result<Vec<u8>> {
    let p = Path::new(path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(st) = std::fs::metadata(p) {
            let mode = st.permissions().mode();
            if mode & 0o077 != 0 {
                eprintln!(
                    "[!] WARNING: {path} is accessible by group/others (permissions {:o}). Recommend setting to 0600.",
                    mode & 0o777
                );
            }
        }
    }
    let text = std::fs::read_to_string(p)
        .map_err(|e| Error::param(format!("Cannot read PSK file {path}: {e}")))?;
    // strip the UTF-8 BOM
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    normalize_psk(text)
}

/// Load the PSK from the ISOSTRESS_PSK environment variable.
/// The value is never opened as a path, even if it happens to be an existing file.
pub fn load_psk_from_env() -> Result<Option<Vec<u8>>> {
    match std::env::var("ISOSTRESS_PSK") {
        Ok(raw) if !raw.is_empty() => Ok(Some(normalize_psk(&raw)?)),
        _ => Ok(None),
    }
}

fn psk_to_hex(psk: &[u8]) -> String {
    hex::encode(psk)
}

/// CLI main entry point.
pub fn main() {
    // Intercept --version manually: print the strict three-part contract string (clap would prefix the
    // program name, disagreeing with the Python-version output specified in the README "Display and Quotation Conventions")
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("{}", crate::version::format_version());
        return;
    }
    let cli = Cli::parse();

    match &cli.command {
        Some(Command::Pskgen) => match generate_psk() {
            Ok(p) => {
                println!("{}", psk_to_hex(&p));
                let mut p = p;
                p.zeroize();
            }
            Err(e) => {
                eprintln!("[!] {e}");
                std::process::exit(1);
            }
        },
        Some(Command::Bench {
            handshakes,
            throughput_mib,
            primitive_iters,
        }) => {
            crate::bench::run_benchmarks(*handshakes, *throughput_mib, *primitive_iters);
        }
        None => {
            let code = run_main_flow(&cli);
            if code != 0 {
                std::process::exit(code);
            }
        }
    }
}

fn run_main_flow(cli: &Cli) -> i32 {
    let role = match cli.role.as_deref() {
        Some("listen") => crate::handshake::Role::Responder,
        Some("connect") => crate::handshake::Role::Initiator,
        Some(other) => {
            eprintln!("[!] --role must be listen or connect, got: {other}");
            return 2;
        }
        None => {
            // No --role: print the usage (part of the clap help is already provided by --help)
            let _ = Cli::command().print_help();
            return 0;
        }
    };

    let host = cli.host.clone().unwrap_or_else(|| {
        if role == crate::handshake::Role::Responder {
            DEFAULT_HOST_LISTEN.to_string()
        } else {
            DEFAULT_HOST_CONNECT.to_string()
        }
    });

    // --- Parameter range validation (invalid values never reach the protocol layer) ---
    if cli.random_len == 0 || !cli.random_len.is_multiple_of(8) {
        eprintln!("[!] random_len must be a positive integer and a multiple of 8");
        return 2;
    }
    if cli.random_len / 8 > MAX_NONCE as u64 {
        eprintln!("[!] random_len/8 must not exceed the access random number limit of 512 bytes");
        return 2;
    }
    if cli.random_rate == 0 {
        eprintln!("[!] random_rate must be a positive integer");
        return 2;
    }
    if cli.window == 0 {
        eprintln!("[!] window must be a positive integer");
        return 2;
    }
    if cli.time_window == 0 {
        eprintln!("[!] time_window must be a positive integer");
        return 2;
    }
    if cli.retry_count == 0 {
        eprintln!("[!] retry_count must be a positive integer");
        return 2;
    }
    if cli.retry_interval <= 0.0 {
        eprintln!("[!] retry_interval must be a positive number");
        return 2;
    }
    if (cli.padding_min.is_none()) != (cli.padding_max.is_none()) {
        eprintln!("[!] --padding-min and --padding-max must be given together");
        return 2;
    }
    if let (Some(pmin), Some(pmax)) = (cli.padding_min, cli.padding_max) {
        if pmin > pmax || pmax > MAX_PAD {
            eprintln!("[!] padding range must satisfy 0 <= min <= max <= {MAX_PAD}");
            return 2;
        }
    }
    if cli.jitter < 0.0 {
        eprintln!("[!] jitter must be non-negative");
        return 2;
    }
    if cli.silent_hold <= 0.0 {
        eprintln!("[!] silent_hold must be a positive number");
        return 2;
    }

    // --- PSK injection (README priority order) ---
    let psk_bytes: Vec<u8> = if let Some(path) = &cli.psk_file {
        match load_psk_from_file(path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[!] {e}");
                return 1;
            }
        }
    } else if cli.psk_env {
        match load_psk_from_env() {
            Ok(Some(p)) => p,
            Ok(None) => {
                eprintln!("[!] Environment variable ISOSTRESS_PSK is not set");
                return 1;
            }
            Err(e) => {
                eprintln!("[!] {e}");
                return 1;
            }
        }
    } else if let Some(p) = &cli.psk {
        // the --psk value is treated as a literal, never opened as a path
        eprintln!("[!] WARNING: command-line --psk is insecure");
        match normalize_psk(p) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[!] {e}");
                return 1;
            }
        }
    } else {
        eprintln!("[!] --psk-file, --psk-env or --psk must be provided");
        return 2;
    };

    let params = match Params::build(
        cli.random_len,
        cli.random_rate,
        cli.window,
        KEY_LEN,
        HASH_NAME.to_string(),
        AEAD_NAME.to_string(),
        serde_json::json!({}),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[!] {e}");
            return 1;
        }
    };

    let cfg = SessionConfig {
        psk: psk_bytes,
        params,
        time_window: cli.time_window,
        padding: cli.padding_min.zip(cli.padding_max),
        jitter: cli.jitter,
        silent_hold: Duration::from_secs_f64(cli.silent_hold),
        handshake_timeout: crate::handshake::HANDSHAKE_TIMEOUT,
        retry_count: cli.retry_count,
        retry_interval: cli.retry_interval,
        rate_limit: cli.rate_limit,
    };

    match run_session(role, &cfg, &host, cli.port) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("[!] {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::format_version;

    #[test]
    fn version_output_via_clap() {
        // --version three-part output
        assert!(format_version().starts_with("ISOSTRESS_RS-1.0.0-20261030"));
    }

    #[test]
    fn psk_hex_roundtrip() {
        let p = generate_psk().unwrap();
        assert_eq!(p.len(), 32);
        let s = psk_to_hex(&p);
        assert_eq!(s.len(), 64);
        let back = normalize_psk(&s).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn psk_base64_accepted() {
        let p = generate_psk().unwrap();
        use base64::Engine;
        let s = base64::engine::general_purpose::STANDARD.encode(&p);
        assert_eq!(normalize_psk(&s).unwrap(), p);
    }

    #[test]
    fn psk_rejects_weak_and_default() {
        assert!(normalize_psk("").is_err());
        assert!(normalize_psk(FORBIDDEN_DEFAULT_PSK).is_err());
        // Low entropy
        assert!(normalize_psk(&hex::encode([1u8; 32])).is_err());
        // Wrong length
        assert!(normalize_psk(&hex::encode([1u8; 16])).is_err());
        assert!(normalize_psk("not-a-psk!!").is_err());
    }

    #[test]
    fn env_psk_never_treated_as_path() {
        // regression: an env value that is an existing path is parsed as a literal (it must fail
        // to parse rather than read the file); a tainted-path implementation would read the dir value and succeed
        let this_file = env!("CARGO_MANIFEST_DIR");
        let err = normalize_psk(this_file);
        assert!(
            err.is_err(),
            "A path string must not be treated as a valid PSK"
        );
    }
}
