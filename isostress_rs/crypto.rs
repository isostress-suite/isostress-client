// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 isostress Suite maintainers

//! Cryptographic primitives layer (Master Guide, Section 4.2 /
//! Appendices F.3-F.5).
//!
//! Default suite: X25519 (see the `kex` module) + HKDF-SHA3-256 +
//! HMAC-SHA3-256 + AES-256-GCM. The hash algorithm is chosen by the
//! parameter hash_name (allowed values: SHA3-256/384/512 and
//! SHA-256/384/512, Appendix F.1); the reference implementation
//! contains only AES-256-GCM (mapped automatically by key_len to
//! AES-128/192/256-GCM, matching Python `AESGCM(key)` behavior).
//!
//! HKDF is implemented directly with HMAC primitives per RFC 5869
//! (two-step Extract-then-Expand), byte-for-byte equivalent to the
//! `HKDF` class of Python's `cryptography` library:
//! - `salt=None` → RFC default all-zero salt (consistent with Python
//!   `HKDF(salt=None)`);
//! - salt is an **independent salt parameter**, not material
//!   concatenated into IKM (Master Guide, Section 4.2.2,
//!   correction item).
//!
//! Security notes:
//! - AEAD decryption failure converges to [`Error::Security`]
//!   (authentication failure means tampering or key mismatch);
//! - Intermediate key material is erased with `zeroize` (Appendix H.6
//!   defense rule: do not leave unerodable heap copies, an earlier
//!   defect class of the Python implementation);
//! - This module is a pure computation library with no process/subprocess
//!   invocation surface.

use hmac::Mac;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::errors::{Error, Result};

pub const X25519_PUB_LEN: usize = 32;
pub const SESSION_SALT_LEN: usize = 32;
pub const NEXT_SEED_LEN: usize = 32;
pub const GCM_NONCE_LEN: usize = 12;

// =============================================================================
// Basic helpers
// =============================================================================

/// Cryptographically secure random bytes.
pub fn secure_random(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).map_err(|e| Error::crypto(format!("random source failure: {e}")))?;
    Ok(buf)
}

/// Constant-time comparison; defends against timing side channels (Appendix F.4 confirmation-tag check).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.ct_eq(b).into()
}

/// HMAC-SHA3-256 (fixed algorithm -- token hash derivation does not follow
/// params.hash_name; see Master Guide, Section 4.1.1, placeholder path).
pub fn hmac_sha3(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = <hmac::Hmac<sha3::Sha3_256> as hmac::Mac>::new_from_slice(key)
        .expect("HMAC accepts arbitrary-length keys");
    mac.update(message);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Entropy check; intercepts obviously weak PSKs (Master Guide Appendix B: blocks only visibly weak keys).
pub fn check_entropy(data: &[u8], min_bits: f64) -> Result<()> {
    if data.is_empty() {
        return Err(Error::param("data is empty"));
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let length = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / length;
            entropy -= p * p.log2();
        }
    }
    if entropy < min_bits {
        return Err(Error::param(format!(
            "PSK entropy too low ({entropy:.2} bits/byte); use a cryptographically secure random source"
        )));
    }
    Ok(())
}

// =============================================================================
// Suite (bound by params.hash_name)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashKind {
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Sha256,
    Sha384,
    Sha512,
}

impl HashKind {
    fn digest_len(self) -> usize {
        match self {
            HashKind::Sha3_256 | HashKind::Sha256 => 32,
            HashKind::Sha3_384 | HashKind::Sha384 => 48,
            HashKind::Sha3_512 | HashKind::Sha512 => 64,
        }
    }
}

/// Set of cryptographic primitives bound by the parameter hash_name.
#[derive(Debug, Clone)]
pub struct CryptoSuite {
    pub hash_name: String,
    pub aead_name: String,
}

impl CryptoSuite {
    pub fn new(hash_name: impl Into<String>, aead_name: impl Into<String>) -> Result<Self> {
        let suite = CryptoSuite {
            hash_name: hash_name.into(),
            aead_name: aead_name.into(),
        };
        if suite.aead_name != "AES-256-GCM" {
            return Err(Error::crypto(format!(
                "unsupported AEAD algorithm: {}, the reference implementation contains only AES-256-GCM",
                suite.aead_name
            )));
        }
        suite.kind()?; // validate that hash_name is valid
        Ok(suite)
    }

    fn kind(&self) -> Result<HashKind> {
        match self.hash_name.as_str() {
            "SHA3-256" => Ok(HashKind::Sha3_256),
            "SHA3-384" => Ok(HashKind::Sha3_384),
            "SHA3-512" => Ok(HashKind::Sha3_512),
            "SHA-256" => Ok(HashKind::Sha256),
            "SHA-384" => Ok(HashKind::Sha384),
            "SHA-512" => Ok(HashKind::Sha512),
            other => Err(Error::crypto(format!(
                "unsupported hash algorithm: {other}; options: SHA3-256, SHA3-384, SHA3-512, SHA-256, SHA-384, SHA-512"
            ))),
        }
    }

    /// HMAC-<hash> (arbitrary-length keys handled per RFC 2104).
    fn mac_bytes(&self, kind: HashKind, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let out = match kind {
            HashKind::Sha3_256 => {
                let mut m = <hmac::Hmac<sha3::Sha3_256> as hmac::Mac>::new_from_slice(key)
                    .map_err(|e| Error::crypto(format!("invalid HMAC key: {e}")))?;
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            HashKind::Sha3_384 => {
                let mut m = <hmac::Hmac<sha3::Sha3_384> as hmac::Mac>::new_from_slice(key)
                    .map_err(|e| Error::crypto(format!("invalid HMAC key: {e}")))?;
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            HashKind::Sha3_512 => {
                let mut m = <hmac::Hmac<sha3::Sha3_512> as hmac::Mac>::new_from_slice(key)
                    .map_err(|e| Error::crypto(format!("invalid HMAC key: {e}")))?;
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            HashKind::Sha256 => {
                let mut m = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key)
                    .map_err(|e| Error::crypto(format!("invalid HMAC key: {e}")))?;
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            HashKind::Sha384 => {
                let mut m = <hmac::Hmac<sha2::Sha384> as hmac::Mac>::new_from_slice(key)
                    .map_err(|e| Error::crypto(format!("invalid HMAC key: {e}")))?;
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            HashKind::Sha512 => {
                let mut m = <hmac::Hmac<sha2::Sha512> as hmac::Mac>::new_from_slice(key)
                    .map_err(|e| Error::crypto(format!("invalid HMAC key: {e}")))?;
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        };
        Ok(out)
    }

    /// HMAC-<hash> (public suite interface).
    pub fn hmac(&self, key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let kind = self.kind()?;
        self.mac_bytes(kind, key, message)
    }

    /// HKDF (RFC 5869): PRK = HMAC(salt, IKM); OKM is derived block by block,
    /// T(i) = HMAC(PRK, T(i-1) ‖ info ‖ counter). `salt=None` → all-zero salt (RFC default).
    /// `info` is a binary-safe byte string; protocol context labels are all ASCII strings.
    pub fn hkdf(
        &self,
        ikm: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
        length_bits: usize,
    ) -> Result<Vec<u8>> {
        let kind = self.kind()?;
        let hash_len = kind.digest_len();
        let len = length_bits / 8;
        if len == 0 || len > 255 * hash_len {
            return Err(Error::crypto(format!("invalid HKDF output length: {len}")));
        }
        // Extract: when salt is absent, use an all-zero key of digest length per RFC
        let mut salt_key: Vec<u8> = match salt {
            Some(s) if !s.is_empty() => s.to_vec(),
            _ => vec![0u8; hash_len],
        };
        let mut prk = self.mac_bytes(kind, &salt_key, ikm)?;
        salt_key.zeroize();
        // Expand: derive block by block
        let n = len.div_ceil(hash_len);
        let mut okm = Vec::with_capacity(n * hash_len);
        let mut t: Vec<u8> = Vec::new();
        let mut block: Vec<u8> = Vec::new();
        for i in 1..=n {
            block.clear();
            block.extend_from_slice(&t);
            block.extend_from_slice(info);
            block.push(i as u8);
            t = self.mac_bytes(kind, &prk, &block)?;
            okm.extend_from_slice(&t);
        }
        block.zeroize();
        t.zeroize();
        prk.zeroize();
        okm.truncate(len);
        Ok(okm)
    }
}

// =============================================================================
// AEAD (Appendix F.5)
// =============================================================================

/// AES-<key_len>-GCM encryption; output = ciphertext ‖ 16B authentication tag.
/// key_len is determined by the key length (16/24/32B), matching Python `AESGCM(key)`.
pub fn aead_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm, Nonce};
    let nonce = Nonce::try_from(nonce)
        .map_err(|_| Error::crypto(format!("invalid nonce length: {}", nonce.len())))?; // 12B
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    match key.len() {
        16 => {
            let c = Aes128Gcm::new_from_slice(key)
                .map_err(|e| Error::crypto(format!("invalid AEAD key: {e}")))?;
            c.encrypt(&nonce, payload)
                .map_err(|e| Error::crypto(format!("AEAD encryption failed: {e}")))
        }
        24 => {
            type Aes192Gcm = AesGcm<aes::Aes192, aes_gcm::aead::consts::U12>;
            let c = Aes192Gcm::new_from_slice(key)
                .map_err(|e| Error::crypto(format!("invalid AEAD key: {e}")))?;
            c.encrypt(&nonce, payload)
                .map_err(|e| Error::crypto(format!("AEAD encryption failed: {e}")))
        }
        32 => {
            let c = Aes256Gcm::new_from_slice(key)
                .map_err(|e| Error::crypto(format!("invalid AEAD key: {e}")))?;
            c.encrypt(&nonce, payload)
                .map_err(|e| Error::crypto(format!("AEAD encryption failed: {e}")))
        }
        n => Err(Error::crypto(format!("invalid AEAD key length: {n}"))),
    }
}

/// AES-GCM decryption and authentication. Any failure converges to [`Error::Security`].
pub fn aead_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm, Nonce};
    let nonce = Nonce::try_from(nonce)
        .map_err(|_| Error::crypto(format!("invalid nonce length: {}", nonce.len())))?;
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    let inner = || -> std::result::Result<Vec<u8>, aes_gcm::Error> {
        match key.len() {
            16 => Aes128Gcm::new_from_slice(key)
                .map_err(|_| aes_gcm::Error)?
                .decrypt(&nonce, payload),
            24 => AesGcm::<aes::Aes192, aes_gcm::aead::consts::U12>::new_from_slice(key)
                .map_err(|_| aes_gcm::Error)?
                .decrypt(&nonce, payload),
            32 => Aes256Gcm::new_from_slice(key)
                .map_err(|_| aes_gcm::Error)?
                .decrypt(&nonce, payload),
            _ => Err(aes_gcm::Error),
        }
    };
    inner().map_err(|_| Error::security("AEAD decryption or integrity check failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_rfc5869_test_case_1() {
        // RFC 5869 Test Case 1 (SHA-256 official reference vector, binary info)
        // Cross-check with an inline independent Extract/Expand implementation built on HMAC primitives, then assert the known RFC prefixes.
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let mac = |k: &[u8], d: &[u8]| -> Vec<u8> {
            let mut m = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(k).unwrap();
            m.update(d);
            m.finalize().into_bytes().to_vec()
        };
        // PRK = HMAC(salt, IKM)
        let prk = mac(&salt, &ikm);
        // T1 = HMAC(PRK, info ‖ 0x01); T2 = HMAC(PRK, T1 ‖ info ‖ 0x02)
        let mut d1 = info.clone();
        d1.push(1);
        let t1 = mac(&prk, &d1);
        let mut d2 = t1.clone();
        d2.extend_from_slice(&info);
        d2.push(2);
        let t2 = mac(&prk, &d2);
        let mut okm_inline = t1.clone();
        okm_inline.extend_from_slice(&t2[..10]); // L = 42B
        assert_eq!(
            hex::encode(&okm_inline[..16]),
            "3cb25f25faacd57a90434f64d0362f2a",
            "inline HKDF must hit the known RFC 5869 TC1 prefix"
        );
        // The suite implementation matches the inline implementation byte-for-byte (all 42 bytes of TC1)
        let suite = CryptoSuite::new("SHA-256", "AES-256-GCM").unwrap();
        let okm = suite.hkdf(&ikm, Some(&salt), &info, 336).unwrap();
        assert_eq!(okm.len(), 42);
        assert_eq!(okm, okm_inline);
    }

    #[test]
    fn hkdf_rfc5869_test_case_3() {
        // RFC 5869 Test Case 3 (SHA-256, zero-length salt and info)
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let suite = CryptoSuite::new("SHA-256", "AES-256-GCM").unwrap();
        let okm = suite.hkdf(&ikm, None, b"", 256).unwrap();
        assert_eq!(
            hex::encode(okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        );
    }

    #[test]
    fn hkdf_none_salt_is_rfc_default() {
        // salt=None → all-zero salt (consistent with Python HKDF(salt=None)): equivalent to explicitly passing an all-zero salt
        let ikm = [0x0b_u8; 22];
        let suite = CryptoSuite::new("SHA-256", "AES-256-GCM").unwrap();
        let a = suite.hkdf(&ikm, None, b"info", 256).unwrap();
        let b = suite.hkdf(&ikm, Some(&[0u8; 32]), b"info", 256).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hkdf_multi_block_matches_python_len() {
        // Output > hash_len takes the multi-block path (SHA3-256 → 32B per block)
        let ikm = [7u8; 32];
        let suite = CryptoSuite::new("SHA3-256", "AES-256-GCM").unwrap();
        let okm = suite
            .hkdf(&ikm, Some(&[1u8; 32]), b"ISOSTRESS-PHASE1-NONCE-v3", 512)
            .unwrap();
        assert_eq!(okm.len(), 64);
    }

    #[test]
    fn unsupported_hash_rejected() {
        assert!(CryptoSuite::new("MD5", "AES-256-GCM").is_err());
        assert!(CryptoSuite::new("SHA3-256", "ChaCha20-Poly1305").is_err());
    }

    #[test]
    fn aead_roundtrip_and_tamper() {
        let key = secure_random(32).unwrap();
        let nonce = [0u8; 12];
        let pt = b"hello isostress";
        let aad = b"routing-aad";
        let ct = aead_encrypt(&key, &nonce, pt, aad).unwrap();
        assert_eq!(ct.len(), pt.len() + 16);
        let back = aead_decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(back, pt);
        // AAD has been tampered with → authentication fails → Security
        assert!(aead_decrypt(&key, &nonce, &ct, b"other").is_err());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(aead_decrypt(&key, &nonce, &bad, aad).is_err());
    }

    #[test]
    fn entropy_check() {
        assert!(check_entropy(&[0u8; 32], 3.5).is_err());
        let r = secure_random(32).unwrap();
        assert!(check_entropy(&r, 3.5).is_ok());
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
