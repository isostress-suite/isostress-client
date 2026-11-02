// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 isostress Suite maintainers

//! ISOSTRESS_RS-1.0.0 — library entry point.
//!
//! The crate root is also the binary entry point (`isostress-rs.rs`), which uses the
//! crate's current flat layout: every module file lives in this directory and is
//! pulled in with `#[path]`. Flatness is the current state, not a collection
//! requirement. This file exists so the crate can **also** be consumed as a library.
//!
//! Why that matters: before this target existed, `isostress-rs` could only ever be run as
//! a binary. A third party could not depend on the protocol implementation, and
//! integration tests could not `use` it (a `tests/` directory cannot see a bin-only
//! crate). The fuzz target in `fuzz/frames.rs` depends on this target for the
//! same reason.
//!
//! Module layout is unchanged and stays flat; only the target type is added.

#[path = "bench.rs"]
pub mod bench;
#[path = "cli.rs"]
pub mod cli;
#[path = "crypto.rs"]
pub mod crypto;
#[path = "errors.rs"]
pub mod errors;
#[path = "frames.rs"]
pub mod frames;
#[path = "handshake.rs"]
pub mod handshake;
#[path = "identity.rs"]
pub mod identity;
#[path = "kex.rs"]
pub mod kex;
#[path = "params.rs"]
pub mod params;
#[path = "session.rs"]
pub mod session;
#[path = "transport.rs"]
pub mod transport;
#[path = "version.rs"]
pub mod version;

// Shared known-answer vectors. Test-only: this module reads test-vectors/vectors.json,
// which is a repository asset, not a runtime dependency. Gating it keeps the release
// binary free of JSON parsing and serde_json in the frame path.
#[cfg(test)]
#[path = "vectors.rs"]
mod vectors;

// Integration tests: real TCP bidirectional flow, CLI contract, defensive-rule
// regression (historic PoC scenarios must be "unbreakable"). They live with the
// library rather than the binary so they can reach the modules directly.
// The end-to-end binary smoke test is covered by interop_test.py.
#[cfg(test)]
#[path = "integration_tests.rs"]
mod tcp_integration;
