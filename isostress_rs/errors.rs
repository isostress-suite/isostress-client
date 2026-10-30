// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 isostress Suite maintainers

//! Protocol-layer error system (a Rust-typed consolidation of Master Guide, Appendix H.5).
//!
//! The exception tree of the Python reference implementation maps one-to-one onto this enum:
//!
//! | Python                    | Rust                          |
//! |---------------------------|-------------------------------|
//! | `ISOSTRESSError`              | [`Error`]                     |
//! | `ISOSTRESSSecurityError`      | [`Error::Security`]           |
//! | `ISOSTRESSParamError`         | [`Error::Param`]              |
//! | `SilentDropError`         | [`Error::SilentDrop`]         |
//! | `ISOSTRESSProtocolError`      | [`Error::Protocol`]           |
//! | `ISOSTRESSCryptoError`        | [`Error::Crypto`]             |
//! | `ISOSTRESSTimeoutError`       | [`Error::Timeout`]            |
//! | `ISOSTRESSError` (generic/desync) | [`Error::Session`]            |
//! | `ConnectionError/OSError` | [`Error::Io`]                 |
//!
//! Handling semantics (H.5):
//! - `Security`: security event — always terminate the session and securely zeroize the keys; not retryable, not ignorable;
//! - `SilentDrop`: signal that **this side has entered strict silence** — once the upper layer catches it, it must
//!   never send any more data to the peer or close the connection (the silent path has taken over, Appendix F.2);
//! - `Protocol`: frame-format issue — in the handshake phase go to silence/disconnect per role; in the data phase terminate the session;
//! - `Crypto`: cryptographic failure (a low-order point is an attack in itself; treat it as a security event);
//! - `Timeout`: a half-packet timeout must be accompanied by forced socket closure (the read layer is responsible).

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// Security event: PSK mismatch, anchor-confirmation failure, replay/out-of-order delivery, session ID mismatch,
    /// AEAD decryption failure, unknown payload format, bidirectional token-hash verification failure, etc.
    Security(String),
    /// Parameter issue: parameters from the two sides mismatch, or a parameter value is illegal.
    Param(String),
    /// Strict-silence signal (Appendix F.2): this side (the responder) has entered silent suspension — sends no
    /// bytes and does not close the connection proactively. The upper layer must no longer write data to or close the peer connection.
    SilentDrop(String),
    /// Frame-format issue: length limit exceeded, invalid JSON, structural length contradiction, nonce length mismatch, etc.
    Protocol(String),
    /// Cryptographic failure: weak DH output (low-order point / all zeros), derivation failure, unsupported algorithm.
    Crypto(String),
    /// Timeout: handshake timeout, read total time limit exhausted, half-packet timeout, no packet in the data stage.
    Timeout(String),
    /// Irreversibly desynced session or other generic protocol error (reconnection is mandatory after a send failure).
    Session(String),
    /// Connection-layer error (peer closed, connection reset, etc.).
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Security(m) => write!(f, "Security error: {m}"),
            Error::Param(m) => write!(f, "Parameter error: {m}"),
            Error::SilentDrop(m) => write!(f, "Silent drop: {m}"),
            Error::Protocol(m) => write!(f, "Protocol error: {m}"),
            Error::Crypto(m) => write!(f, "Cryptographic error: {m}"),
            Error::Timeout(m) => write!(f, "Timeout error: {m}"),
            Error::Session(m) => write!(f, "Session error: {m}"),
            Error::Io(e) => write!(f, "Connection error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl Error {
    pub fn security(msg: impl Into<String>) -> Self {
        Error::Security(msg.into())
    }
    pub fn param(msg: impl Into<String>) -> Self {
        Error::Param(msg.into())
    }
    pub fn silent_drop(msg: impl Into<String>) -> Self {
        Error::SilentDrop(msg.into())
    }
    pub fn protocol(msg: impl Into<String>) -> Self {
        Error::Protocol(msg.into())
    }
    pub fn crypto(msg: impl Into<String>) -> Self {
        Error::Crypto(msg.into())
    }
    pub fn timeout(msg: impl Into<String>) -> Self {
        Error::Timeout(msg.into())
    }
    pub fn session(msg: impl Into<String>) -> Self {
        Error::Session(msg.into())
    }

    /// Connection closed by the peer (used by the recv loop to distinguish a "normal close" from a "security event").
    pub fn connection_closed(msg: impl AsRef<str>) -> Self {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            msg.as_ref(),
        ))
    }

    pub fn is_silent_drop(&self) -> bool {
        matches!(self, Error::SilentDrop(_))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
