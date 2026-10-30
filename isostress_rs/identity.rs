// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 isostress Suite maintainers

//! P2P placeholder token hash (Master Guide, section 4.1.1, "P2P direct-connection placeholder path without TCA").
//!
//! Without a TCA token, both sides derive placeholder door numbers from the PSK, ensuring that the Phase 1 identity_blob and
//! the Phase 4 token hash are consistent under bidirectional verification:
//!
//! ```text
//! placeholder hash = first 32 bytes of HMAC-SHA3-256(PSK, role label)
//! initiator's own = HMAC(PSK, "ISOSTRESS-TOKEN-INITIATOR-v3")
//! responder's own = HMAC(PSK, "ISOSTRESS-TOKEN-RESPONDER-v3")
//! ```
//!
//! This way A's local hash is exactly B's peer hash (A.local == B.peer, A.peer == B.local),
//! and src/dst stay naturally symmetric from each side's viewpoint. This path only guarantees frame-structure integrity and binds identity to the PSK;
//! it does not have TCA's "third-party notary" property.

use crate::crypto::hmac_sha3;

pub const TOKEN_LABEL_INITIATOR: &[u8] = b"ISOSTRESS-TOKEN-INITIATOR-v3";
pub const TOKEN_LABEL_RESPONDER: &[u8] = b"ISOSTRESS-TOKEN-RESPONDER-v3";

pub const TOKEN_HASH_LEN: usize = 32;

pub const ROLE_INITIATOR: &str = "initiator";
pub const ROLE_RESPONDER: &str = "responder";

/// Derive (local hash, peer hash) per role.
///
/// Initiator's view: local=HMAC(INITIATOR label), peer=HMAC(RESPONDER label);
/// Responder's view: the two labels are swapped.
pub fn derive_p2p_identity(psk: &[u8], role: &str) -> crate::errors::Result<([u8; 32], [u8; 32])> {
    let (my_label, peer_label) = match role {
        ROLE_INITIATOR => (TOKEN_LABEL_INITIATOR, TOKEN_LABEL_RESPONDER),
        ROLE_RESPONDER => (TOKEN_LABEL_RESPONDER, TOKEN_LABEL_INITIATOR),
        _ => {
            return Err(crate::errors::Error::param(format!(
                "role must be '{ROLE_INITIATOR}' or '{ROLE_RESPONDER}'"
            )))
        }
    };
    let local_hash = hmac_sha3(psk, my_label);
    let peer_hash = hmac_sha3(psk, peer_label);
    Ok((local_hash, peer_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p2p_hashes_cross_match() {
        let psk: Vec<u8> = (0u8..32).collect();
        let (a_local, a_peer) = derive_p2p_identity(&psk, ROLE_INITIATOR).unwrap();
        let (b_local, b_peer) = derive_p2p_identity(&psk, ROLE_RESPONDER).unwrap();
        // A's local hash is exactly B's peer hash (keeps the Phase 4 bidirectional check self-consistent)
        assert_eq!(a_local, b_peer);
        assert_eq!(a_peer, b_local);
        assert_ne!(a_local, a_peer);
        // Byte-for-byte match with the spec formula: HMAC-SHA3-256(PSK, label)
        assert_eq!(a_local, hmac_sha3(&psk, TOKEN_LABEL_INITIATOR));
        assert_eq!(b_local, hmac_sha3(&psk, TOKEN_LABEL_RESPONDER));
    }

    #[test]
    fn identity_rejects_bad_role() {
        let psk = [7u8; 32];
        assert!(derive_p2p_identity(&psk, "middle").is_err());
    }
}
