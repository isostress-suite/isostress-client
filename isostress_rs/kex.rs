// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 isostress Suite maintainers

//! X25519 key agreement (Master Guide, section 4.2.2 steps 1-3 / Appendix F.3).
//!
//! Each session generates a one-time ephemeral scalar (private key); the peer only sees the 32B Raw public key.
//! Failure criteria (Appendix F.3; any of the following yields [`Error::Crypto`], handled as a low-order point attack):
//! - peer public key length is not 32 bytes;
//! - the shared secret output is all zeros (the mathematical signature of a malicious public key collapsing the secret to a constant).
//!
//! The ephemeral scalar is automatically zeroized when the object is dropped (Drop + zeroize), equivalent to the Python side's
//! "destroy ephemeral private key" (4.2.2 step 5) as the forward-secrecy engineering implementation.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::crypto::{secure_random, X25519_PUB_LEN};
use crate::errors::{Error, Result};

/// X25519 base point (RFC 7748: u = 9, 32 bytes little-endian).
const BASEPOINT: [u8; 32] = {
    let mut bp = [0u8; 32];
    bp[0] = 9;
    bp
};

/// One-time ephemeral private key. Automatically zeroized on Drop.
pub struct EphemeralSecret {
    scalar: [u8; 32],
}

impl EphemeralSecret {
    /// Generates a 32B random ephemeral scalar (clamped per the RFC 7748 specification during X25519 computation).
    pub fn generate() -> Result<Self> {
        let v = secure_random(32)?;
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&v);
        drop(v);
        Ok(EphemeralSecret { scalar })
    }

    /// The corresponding public key (32B Raw encoding, byte-for-byte identical to Python's `Encoding.Raw`).
    pub fn public_bytes(&self) -> [u8; 32] {
        x25519_dalek::x25519(self.scalar, BASEPOINT)
    }

    /// Constructs an ephemeral secret from a caller-supplied scalar.
    ///
    /// **Only for known-answer tests.** RFC 7748 supplies fixed scalars, and the shared
    /// test-vector file replays them; [`EphemeralSecret::generate`] is random by
    /// construction and cannot reproduce them. Production code must use `generate()` —
    /// handing in a chosen scalar would be a catastrophic key-reuse bug, hence the
    /// `test_` prefix and the `#[cfg(test)]` gate.
    #[cfg(test)]
    pub(crate) fn from_scalar_for_test(scalar: [u8; 32]) -> Self {
        EphemeralSecret { scalar }
    }

    /// Computes the shared secret. Failure criteria: see the module docs; on success returns the 32B shared secret.
    pub fn shared_secret(&self, peer_public_bytes: &[u8]) -> Result<[u8; 32]> {
        if peer_public_bytes.len() != X25519_PUB_LEN {
            return Err(Error::crypto("peer public key length is invalid"));
        }
        let mut peer = [0u8; 32];
        peer.copy_from_slice(peer_public_bytes);
        let shared = x25519_dalek::x25519(self.scalar, peer);
        peer.zeroize();
        // Low-order point check: an all-zero output is treated as an attack (Appendix F.3)
        if bool::from(shared.ct_eq(&[0u8; 32])) {
            return Err(Error::crypto(
                "weak DH output detected (all zero); possible small-subgroup attack",
            ));
        }
        Ok(shared)
    }
}

impl Drop for EphemeralSecret {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_secret_symmetry() {
        let a = EphemeralSecret::generate().unwrap();
        let b = EphemeralSecret::generate().unwrap();
        let pk_a = a.public_bytes();
        let pk_b = b.public_bytes();
        let s1 = a.shared_secret(&pk_b).unwrap();
        let s2 = b.shared_secret(&pk_a).unwrap();
        assert_eq!(s1, s2);
        assert_ne!(s1, [0u8; 32]);
    }

    #[test]
    fn rejects_low_order_and_bad_length() {
        let a = EphemeralSecret::generate().unwrap();
        // All-zero public key (low-order point)
        assert!(a.shared_secret(&[0u8; 32]).is_err());
        // Abnormal length
        assert!(a.shared_secret(&[1u8; 31]).is_err());
        assert!(a.shared_secret(&[1u8; 33]).is_err());
    }

    #[test]
    fn rfc7748_test_vector() {
        // RFC 7748 §6.1 Diffie-Hellman test vector
        let alice_scalar =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap();
        let bob_pub =
            hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .unwrap();
        let expect = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        let mut s = [0u8; 32];
        s.copy_from_slice(&alice_scalar);
        let secret = EphemeralSecret { scalar: s };
        let mut p = [0u8; 32];
        p.copy_from_slice(&bob_pub);
        let shared = secret.shared_secret(&p).unwrap();
        assert_eq!(hex::encode(shared), expect);
    }
}
