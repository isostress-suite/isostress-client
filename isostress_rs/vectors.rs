// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 isostress Suite maintainers

//! isostress 共享测试向量 —— Rust 侧消费者。
//!
//! 读的是 `isostress-client/test-vectors/vectors.json`，与 `isostress_py/tests/test_vectors.py`
//! **同一份文件**。这不是「Rust 抄 Python 的答案」：JSON 是提交进仓的产物，
//! 其中 RFC 5869 / RFC 7748 两条来自 RFC 原文（外部来源），协议向量在生成后经人工复核。
//!
//! 没有这份文件时，两个实现各自的单测都可能是绿的而线上互不通——
//! 单测证明不了「两侧对同一输入产出同一字节」，只有共享期望值能。

use std::fs;

use serde_json::Value;

use crate::crypto::CryptoSuite;
use crate::frames::{build_aad, gcm_nonce, pack_confirm, pack_initiator_key, pack_responder_key};
use crate::kex::EphemeralSecret;

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("vector contains invalid hex")
}

fn doc() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors/vectors.json");
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read shared vectors at {path}: {e}"));
    serde_json::from_str(&raw).expect("shared vectors are not valid JSON")
}

fn vec_of<'a>(d: &'a Value, kind: &str) -> Vec<&'a Value> {
    d["vectors"]
        .as_array()
        .expect("vectors must be an array")
        .iter()
        .filter(|v| v["kind"] == kind)
        .collect()
}

/// 向量里的 hash_name → CryptoSuite。AEAD 固定 AES-256-GCM（唯一实现）。
fn suite(hash_name: &str) -> CryptoSuite {
    CryptoSuite::new(hash_name, "AES-256-GCM").expect("hash from vector")
}

fn s(v: &Value, k: &str) -> String {
    v[k].as_str().expect("string field").to_string()
}
fn n(v: &Value, k: &str) -> u64 {
    v[k].as_u64().expect("numeric field")
}

#[test]
fn shared_vector_file_is_present_and_populated() {
    let d = doc();
    let n = d["vectors"].as_array().expect("vectors array").len();
    assert!(n >= 9, "shared vector file has only {n} entries");
}

/// 向量里的 HKDF label 必须与 handshake.rs 的常量逐字一致。
#[test]
fn protocol_labels_match_source_constants() {
    let d = doc();
    let l = &d["labels"];
    assert_eq!(
        l["INFO_MK"].as_str().unwrap().as_bytes(),
        crate::handshake::INFO_MK
    );
    assert_eq!(
        l["INFO_ANCHOR"].as_str().unwrap().as_bytes(),
        crate::handshake::INFO_ANCHOR
    );
    assert_eq!(
        l["INFO_EK"].as_str().unwrap().as_bytes(),
        crate::handshake::INFO_EK
    );
    assert_eq!(
        l["INFO_SID"].as_str().unwrap().as_bytes(),
        crate::handshake::INFO_SID
    );
    assert_eq!(
        l["INFO_EK_ROTATE"].as_str().unwrap().as_bytes(),
        crate::handshake::INFO_EK_ROTATE
    );
    assert_eq!(
        l["INFO_CONFIRM_INIT"].as_str().unwrap().as_bytes(),
        crate::handshake::INFO_CONFIRM_INIT
    );
    assert_eq!(
        l["INFO_CONFIRM_RESP"].as_str().unwrap().as_bytes(),
        crate::handshake::INFO_CONFIRM_RESP
    );
}

/// RFC 5869 A.1 / A.3：外部来源常量，验证 HKDF 本身。
#[test]
fn hkdf_matches_rfc5869() {
    let d = doc();
    let vs = vec_of(&d, "hkdf");
    assert!(!vs.is_empty(), "no HKDF vectors");
    for v in vs {
        let sc = suite(&s(v, "hash"));
        let got = sc
            .hkdf(
                &hex(&s(v, "ikm")),
                Some(&hex(&s(v, "salt"))),
                &hex(&s(v, "info")),
                n(v, "length_bits") as usize,
            )
            .expect("hkdf");
        assert_eq!(hex::encode(&got), s(v, "okm"), "vector {}", s(v, "name"));
        assert_eq!((got.len() * 8) as u64, n(v, "length_bits"));
    }
}

/// RFC 7748 §6.1：外部来源常量。
#[test]
fn x25519_matches_rfc7748() {
    let d = doc();
    let vs = vec_of(&d, "x25519");
    assert!(!vs.is_empty(), "no X25519 vectors");
    for v in vs {
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&hex(&s(v, "scalar")));
        let secret = EphemeralSecret::from_scalar_for_test(scalar);
        let shared = secret
            .shared_secret(&hex(&s(v, "peer_public")))
            .expect("dh against RFC peer key");
        assert_eq!(
            hex::encode(shared),
            s(v, "shared"),
            "vector {}",
            s(v, "name")
        );
    }
}

/// 协议推导链全段比对：PSK‖DH → MK → anchor → session_id → 方向性 EK → 棘轮。
#[test]
fn session_derivation_chain() {
    let d = doc();
    let vs = vec_of(&d, "session");
    assert!(!vs.is_empty(), "no session vectors");
    for v in vs {
        let sc = suite(&s(v, "hash"));
        let key_len = n(v, "key_len_bits") as usize;
        let psk = hex(&s(v, "psk"));
        let salt = hex(&s(v, "session_salt"));
        let peer_pub_b = hex(&s(v, "pk_b"));

        let mut sk_a = [0u8; 32];
        sk_a.copy_from_slice(&hex(&s(v, "sk_a")));
        let a = EphemeralSecret::from_scalar_for_test(sk_a);
        let dh = a.shared_secret(&peer_pub_b).expect("dh");
        assert_eq!(hex::encode(dh), s(v, "dh"), "{}: dh", s(v, "name"));

        let mut ikm = psk.clone();
        ikm.extend_from_slice(&dh);
        let mk = sc
            .hkdf(&ikm, Some(&salt), crate::handshake::INFO_MK, key_len)
            .expect("mk");
        assert_eq!(hex::encode(&mk), s(v, "mk"), "{}: mk", s(v, "name"));

        let anchor = sc.hmac(&mk, crate::handshake::INFO_ANCHOR).expect("anchor");
        assert_eq!(
            hex::encode(&anchor),
            s(v, "anchor"),
            "{}: anchor",
            s(v, "name")
        );

        let sid_full = sc
            .hkdf(&anchor, None, crate::handshake::INFO_SID, 256)
            .expect("sid");
        let session_id = &sid_full[..32];
        assert_eq!(
            hex::encode(session_id),
            s(v, "session_id"),
            "{}: sid",
            s(v, "name")
        );

        let mut ikm_a = mk.clone();
        ikm_a.extend_from_slice(&anchor);
        ikm_a.push(0x01);
        let init_send = sc
            .hkdf(&ikm_a, None, crate::handshake::INFO_EK, key_len)
            .expect("ek init send");
        let mut ikm_b = mk.clone();
        ikm_b.extend_from_slice(&anchor);
        ikm_b.push(0x02);
        let init_recv = sc
            .hkdf(&ikm_b, None, crate::handshake::INFO_EK, key_len)
            .expect("ek init recv");
        let resp_send = init_recv.clone();
        let resp_recv = init_send.clone();

        assert_eq!(
            hex::encode(&init_send),
            s(v, "initiator_send_ek"),
            "{}: is",
            s(v, "name")
        );
        assert_eq!(
            hex::encode(&init_recv),
            s(v, "initiator_recv_ek"),
            "{}: ir",
            s(v, "name")
        );
        assert_eq!(
            hex::encode(&resp_send),
            s(v, "responder_send_ek"),
            "{}: rs",
            s(v, "name")
        );
        assert_eq!(
            hex::encode(&resp_recv),
            s(v, "responder_recv_ek"),
            "{}: rr",
            s(v, "name")
        );

        let mut rot_in = init_send.clone();
        rot_in.extend_from_slice(&hex(&s(v, "next_seed")));
        let rotated = sc
            .hkdf(&rot_in, None, crate::handshake::INFO_EK_ROTATE, key_len)
            .expect("rotate");
        assert_eq!(
            hex::encode(&rotated),
            s(v, "rotated_ek"),
            "{}: rotate",
            s(v, "name")
        );

        // 对端用接收密钥转完必须得到同一值，否则棘轮两端分叉
        let mut peer_in = resp_recv.clone();
        peer_in.extend_from_slice(&hex(&s(v, "next_seed")));
        let peer_rotated = sc
            .hkdf(&peer_in, None, crate::handshake::INFO_EK_ROTATE, key_len)
            .expect("peer rotate");
        assert_eq!(rotated, peer_rotated, "{}: ratchet diverged", s(v, "name"));
    }
}

/// 两套哈希各一份：只测一套时另一套的回归无人发现。
#[test]
fn session_vectors_cover_both_documented_hash_suites() {
    let d = doc();
    let hashes: Vec<String> = vec_of(&d, "session").iter().map(|v| s(v, "hash")).collect();
    assert!(
        hashes.iter().any(|h| h == "SHA3-256"),
        "no SHA3-256 session vector"
    );
    assert!(
        hashes.iter().any(|h| h == "SHA-256"),
        "no SHA-256 session vector"
    );
}

/// 握手帧逐字节布局（附录 F.3 / F.4）。
#[test]
fn handshake_frame_bytes() {
    let d = doc();
    for v in vec_of(&d, "frame") {
        let name = s(v, "name");
        if name != "frames-phase2-phase3" {
            continue;
        }
        let mut pk = [0u8; 32];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut salt = [0u8; 32];
        for (i, b) in salt.iter_mut().enumerate() {
            *b = (i + 32) as u8;
        }
        let mut pk2 = [0u8; 32];
        for (i, b) in pk2.iter_mut().enumerate() {
            *b = (i + 64) as u8;
        }
        let mut tag = [0u8; 32];
        for (i, b) in tag.iter_mut().enumerate() {
            *b = (i + 96) as u8;
        }

        assert_eq!(
            hex::encode(pack_initiator_key(&pk, &salt).expect("pack")),
            s(v, "initiator_key")
        );
        assert_eq!(
            hex::encode(pack_responder_key(&pk2).expect("pack")),
            s(v, "responder_key")
        );
        assert_eq!(
            hex::encode(pack_confirm(&tag).expect("pack")),
            s(v, "confirm")
        );
        assert_eq!(
            pack_initiator_key(&pk, &salt).expect("pack").len() as u64,
            n(v, "initiator_key_len")
        );
        assert_eq!(
            pack_responder_key(&pk2).expect("pack").len() as u64,
            n(v, "responder_key_len")
        );
        assert_eq!(
            pack_confirm(&tag).expect("pack").len() as u64,
            n(v, "confirm_len")
        );
    }
}

/// nonce 与 AAD 的构造（附录 F.5），seq 铺满整个 uint64 域。
#[test]
fn nonce_and_aad_bytes() {
    let d = doc();
    for v in vec_of(&d, "frame") {
        let name = s(v, "name");
        if name != "frames-phase4-nonce-aad" {
            continue;
        }
        let sid = hex(&s(v, "session_id"));
        let seq = n(v, "seq");
        let seq_max = n(v, "seq_max");
        assert_eq!(hex::encode(gcm_nonce(seq)), s(v, "nonce_seq0"));
        assert_eq!(hex::encode(build_aad(&sid, seq)), s(v, "aad_seq0"));
        assert_eq!(hex::encode(gcm_nonce(seq_max)), s(v, "nonce_seq_max"));
        assert_eq!(hex::encode(build_aad(&sid, seq_max)), s(v, "aad_seq_max"));
        assert_eq!(
            &gcm_nonce(seq)[..4],
            &[0u8; 4],
            "nonce prefix must stay zero"
        );
        assert_eq!(
            &gcm_nonce(seq_max)[..4],
            &[0u8; 4],
            "nonce prefix must stay zero"
        );
    }
}

/// 固定输入下的确定性密文：两侧密文不同 = payload 布局或 AAD 不同。
#[test]
fn aead_deterministic_ciphertext() {
    let d = doc();
    for v in vec_of(&d, "aead") {
        let ct = crate::crypto::aead_encrypt(
            &hex(&s(v, "key")),
            &hex(&s(v, "nonce")),
            &hex(&s(v, "plaintext")),
            &hex(&s(v, "aad")),
        )
        .expect("aead encrypt");
        assert_eq!(
            hex::encode(&ct),
            s(v, "ciphertext"),
            "vector {}",
            s(v, "name")
        );
        let pt = crate::crypto::aead_decrypt(
            &hex(&s(v, "key")),
            &hex(&s(v, "nonce")),
            &ct,
            &hex(&s(v, "aad")),
        )
        .expect("aead decrypt");
        assert_eq!(hex::encode(&pt), s(v, "plaintext"));
    }
}
