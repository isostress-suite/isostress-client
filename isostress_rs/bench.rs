// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 isostress Suite maintainers

//! Benchmark tests (main capability of the benchmark platform).
//!
//! Three benchmark groups, all run over the local loopback:
//! 1. `handshake`: end-to-end latency of the full four-phase handshake, covering X25519, 5x HKDF, 3x HMAC, frame encode/decode and all verification paths, reporting mean/P50/P95 and handshakes per second;
//! 2. `throughput`: one-way data throughput of an established session, including per-packet ratchet rotation, AES-GCM and timestamp verification, i.e. the reachable throughput of the real protocol path;
//! 3. `primitives`: cryptographic primitive micro-benchmarks for X25519 key generation and shared secret, HKDF, HMAC-SHA3-256, AES-256-GCM and SHA3-256.
//!
//! Results serve as performance baselines for cross-language implementations
//! (ISOSTRESS_PY / ISOSTRESS_RS / ...).

use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::crypto::{aead_decrypt, aead_encrypt, hmac_sha3, secure_random, CryptoSuite};
use crate::handshake::{HandshakePeer, Role};
use crate::kex::EphemeralSecret;
use crate::params::{Params, TIME_WINDOW};
use crate::session::SecureSession;
use sha3::Digest;

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = (((sorted.len() as f64) - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn fmt_us(d: Duration) -> String {
    let us = d.as_secs_f64() * 1e6;
    if us >= 1e6 {
        format!("{:.2} s", us / 1e6)
    } else if us >= 1e3 {
        format!("{:.2} ms", us / 1e3)
    } else {
        format!("{:.2} µs", us)
    }
}

fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).expect("connect loopback");
    let (server, _) = listener.accept().expect("accept loopback");
    (client, server)
}

fn bench_handshake(rounds: usize) {
    println!(
        "\n=== Handshake benchmark (full four-phase, loopback TCP, {} rounds) ===",
        rounds
    );
    let psk = vec![0x5Au8; 32];
    let params = Params::new().expect("default params");
    let mut samples: Vec<Duration> = Vec::with_capacity(rounds);
    for i in 0..rounds {
        let (mut a, b) = pair();
        let mut init = HandshakePeer::new(
            psk.clone(),
            params.clone(),
            Role::Initiator,
            None,
            0.0,
            TIME_WINDOW,
            Duration::from_millis(100),
            Duration::from_secs(10),
        )
        .expect("peer");
        let mut resp = HandshakePeer::new(
            psk.clone(),
            params.clone(),
            Role::Responder,
            None,
            0.0,
            TIME_WINDOW,
            Duration::from_millis(100),
            Duration::from_secs(10),
        )
        .expect("peer");
        let started = Instant::now();
        let h = std::thread::spawn(move || init.perform_handshake(&mut a));
        let mut b2 = b.try_clone().expect("clone stream for handshake");
        let m2 = resp
            .perform_handshake(&mut b2)
            .expect("responder handshake");
        let m1 = h.join().expect("join").expect("initiator handshake");
        assert_eq!(
            m1.session_id, m2.session_id,
            "round {i} session IDs should match"
        );
        samples.push(started.elapsed());
        drop(SecureSession::new(m1));
        drop(SecureSession::new(m2));
    }
    let mut sorted = samples.clone();
    sorted.sort();
    let mean: Duration = samples.iter().sum::<Duration>() / samples.len() as u32;
    let p50 = percentile(&sorted, 0.50);
    let p95 = percentile(&sorted, 0.95);
    let per_sec = samples.len() as f64 / sorted.iter().sum::<Duration>().as_secs_f64();
    println!(
        "  Mean: {}  P50: {}  P95: {}",
        fmt_us(mean),
        fmt_us(p50),
        fmt_us(p95)
    );
    println!("  Throughput: {:.1} handshakes/s", per_sec);
}

fn bench_throughput(mib: usize, packet_payload: usize) {
    println!(
        "\n=== Session throughput benchmark (one-way {} MiB, {} B payload/packet, incl. per-packet ratchet) ===",
        mib, packet_payload
    );
    let psk = vec![0x33u8; 32];
    let params = Params::new().expect("default params");
    let (mut a, b) = pair();
    let mut init = HandshakePeer::new(
        psk.clone(),
        params.clone(),
        Role::Initiator,
        None,
        0.0,
        TIME_WINDOW,
        Duration::from_millis(100),
        Duration::from_secs(10),
    )
    .expect("peer");
    let mut resp = HandshakePeer::new(
        psk,
        params,
        Role::Responder,
        None,
        0.0,
        TIME_WINDOW,
        Duration::from_millis(100),
        Duration::from_secs(10),
    )
    .expect("peer");
    let (m1, m2) = {
        // The handshake thread uses a handle clone of b (same socket); b is kept as the receiver
        let mut b_hs = b.try_clone().expect("clone stream for handshake");
        let h = std::thread::spawn(move || resp.perform_handshake(&mut b_hs));
        let m1 = init.perform_handshake(&mut a).expect("initiator handshake");
        let m2 = h.join().expect("join").expect("responder handshake");
        (m1, m2)
    };
    let sender = SecureSession::new(m1);
    let receiver = SecureSession::new(m2);
    let mut send_sock = a;
    let mut recv_sock = b;
    send_sock.set_nodelay(true).ok();

    let total_bytes = mib * 1024 * 1024;
    let payload = vec![0x42u8; packet_payload];
    let per_packet_wire = 44 + packet_payload + 16;
    let n_packets = total_bytes / packet_payload;
    let recv_expected = n_packets * packet_payload;

    let rx = std::thread::spawn(move || {
        let mut got = 0usize;
        while got < recv_expected {
            let data = receiver
                .recv_packet(&mut recv_sock)
                .expect("recv during bench");
            got += data.len();
        }
        got
    });

    let started = Instant::now();
    for _ in 0..n_packets {
        sender
            .send_packet(&mut send_sock, &payload)
            .expect("send during bench");
    }
    let sent_bytes = rx.join().expect("rx thread");
    let elapsed = started.elapsed().as_secs_f64();

    println!(
        "  Delivered: {:.2} MiB / {:.3} s",
        sent_bytes as f64 / (1024.0 * 1024.0),
        elapsed
    );
    println!(
        "  Plaintext throughput: {:.2} MiB/s ({:.1} MB/s)  wire overhead ~{:.0} B/packet",
        sent_bytes as f64 / (1024.0 * 1024.0) / elapsed,
        sent_bytes as f64 / elapsed / 1e6,
        per_packet_wire - packet_payload
    );
    println!(
        "  Packet rate: {:.0} pps (one HKDF ratchet rotation per packet)",
        n_packets as f64 / elapsed
    );
}

fn bench_primitives(iters: usize) {
    println!("\n=== Primitive micro-benchmarks ({iters} iters / or by duration) ===");

    // X25519: key generation + shared secret
    {
        let started = Instant::now();
        for _ in 0..iters {
            let a = EphemeralSecret::generate().unwrap();
            let b = EphemeralSecret::generate().unwrap();
            let pk = b.public_bytes();
            let _ = a.shared_secret(&pk).unwrap();
        }
        let el = started.elapsed();
        println!(
            "  X25519 keygen+shared secret: {:.0} /s ({} each)",
            iters as f64 / el.as_secs_f64(),
            fmt_us(el / iters as u32)
        );
    }

    // HKDF-SHA3-256 (default derivation: 32B output)
    {
        let suite = CryptoSuite::new("SHA3-256", "AES-256-GCM").unwrap();
        let ikm = secure_random(64).unwrap();
        let salt = secure_random(32).unwrap();
        let started = Instant::now();
        for _ in 0..iters {
            let _ = suite
                .hkdf(&ikm, Some(&salt), b"ISOSTRESS-MK-v3", 256)
                .unwrap();
        }
        let el = started.elapsed();
        println!(
            "  HKDF-SHA3-256(32B out): {:.0} /s ({} each)",
            iters as f64 / el.as_secs_f64(),
            fmt_us(el / iters as u32)
        );
    }

    // HMAC-SHA3-256 (64B message)
    {
        let key = secure_random(32).unwrap();
        let msg = secure_random(64).unwrap();
        let started = Instant::now();
        for _ in 0..iters {
            let _ = hmac_sha3(&key, &msg);
        }
        let el = started.elapsed();
        println!(
            "  HMAC-SHA3-256(64B): {:.0} /s ({} each)",
            iters as f64 / el.as_secs_f64(),
            fmt_us(el / iters as u32)
        );
    }

    // AES-256-GCM: 1 KiB plaintext encryption/decryption throughput
    {
        let key = secure_random(32).unwrap();
        // The nonce is deliberately reused across iterations: this benchmark isolates
        // AEAD throughput, not nonce hygiene. Production code must never reuse a GCM nonce.
        let nonce = [0u8; 12];
        let pt = vec![0u8; 1024];
        let aad = b"routing-aad";
        let rounds = iters.max(1);
        let started = Instant::now();
        let mut cts = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            cts.push(aead_encrypt(&key, &nonce, &pt, aad).unwrap());
        }
        let enc_time = started.elapsed();
        let started = Instant::now();
        for ct in &cts {
            let _ = aead_decrypt(&key, &nonce, ct, aad).unwrap();
        }
        let dec_time = started.elapsed();
        let bytes = (pt.len() * rounds) as f64;
        println!(
            "  AES-256-GCM encrypt(1KiB): {:.1} MB/s  decrypt: {:.1} MB/s",
            bytes / enc_time.as_secs_f64() / 1e6,
            bytes / dec_time.as_secs_f64() / 1e6
        );
    }

    // SHA3-256: 1 MiB hash throughput
    {
        let data = vec![0u8; 1024 * 1024];
        let started = Instant::now();
        let mut h = sha3::Sha3_256::new();
        for _ in 0..8 {
            h.update(&data);
        }
        let _ = h.finalize();
        let el = started.elapsed().as_secs_f64();
        println!("  SHA3-256: {:.1} MB/s", (data.len() * 8) as f64 / el / 1e6);
    }
}

/// Benchmark entry point.
pub fn run_benchmarks(handshakes: usize, throughput_mib: usize, primitive_iters: usize) {
    println!(
        "{} benchmark platform (loopback TCP, default params)",
        crate::version::format_version()
    );
    bench_handshake(handshakes.max(5));
    bench_throughput(throughput_mib.max(1), 16384);
    bench_primitives(primitive_iters.max(100));
    println!("\n[+] Benchmarks complete. Results serve as performance baselines for cross-language implementations (ISOSTRESS_PY / ISOSTRESS_RS).");
}
