// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 isostress Suite maintainers

//! Protocol parameter set (Master Guide, Appendix B / F.1).
//!
//! All parameters can be freely declared by the server operator in their own library; both
//! communicating parties must match exactly before access. On-the-wire structure of the parameter JSON: keys in lexicographic order, compact separators, UTF-8
//! (F.1 — exactly 120 bytes under default parameters). The parameter JSON carries **no version or protocol
//! identifier fields at all**: the documentation-to-code correspondence is maintained by a bidirectional declaration, not written into on-the-wire data.
//!
//! All type/value errors of peer-controllable input (`from_value`) are uniformly converged into
//! [`Error::Param`] - panics or the escape of other exceptions is absolutely forbidden (Appendix H.4).

use serde_json::{Map, Value};

use crate::errors::{Error, Result};

// --- Default parameters (Appendix B.1) ---
pub const RANDOM_LEN: u64 = 256; // Connection nonce length (bits, multiple of 8)
pub const RANDOM_RATE: u64 = 1024; // Random generation rate (counts/sec)
pub const WINDOW: u64 = 60; // Negotiation window (seconds; both sides must agree; not the timestamp window)
pub const TIME_WINDOW: u64 = 30; // Timestamp window (seconds, per-peer configurable)
pub const KEY_LEN: u64 = 256; // Session key length (bits, 128/192/256 only)
pub const HASH_NAME: &str = "SHA3-256";
pub const AEAD_NAME: &str = "AES-256-GCM";

// --- Cap constants (Appendix F.6; every cap check must run before the corresponding payload is read) ---
pub const MAX_PARAM_JSON: usize = 4096; // Phase 1 param_json
pub const MAX_IDENTITY: usize = 8192; // Phase 1 identity_blob
pub const MAX_NONCE: usize = 512; // Phase 1 connection nonce
pub const MAX_CIPHERTEXT: usize = 1 << 20; // Phase 4 ct_len (1 MiB)
pub const MAX_PAD: usize = 2048; // Phase 4 random padding
/// User plaintext cap = 1 MiB - 64 - fmt(1) - token hash(64) - ts(8) - next_seed(32) - pad_len(2) - MAX_PAD
pub const MAX_PLAINTEXT: usize = (1 << 20) - 64 - 1 - 64 - 8 - 32 - 2 - MAX_PAD; // 1046357

// module_flags validation caps (guard against recursion bombs / node explosion, F.1)
pub const MAX_FLAG_DEPTH: usize = 32;
pub const MAX_FLAG_NODES: usize = 1024;

/// module_flags validation (F.1): keys must be strings; values only str/int/float/bool/
/// list/dict/null; nesting depth <= 32, total node count <= 1024. Explicit stack iteration instead of recursion,
/// so peer-controlled deep nesting cannot overflow the stack. Node counting and depth rules line up with the Python reference implementation `validate_module_flags`
/// (list items count toward nodes; only dicts advance depth).
pub fn validate_module_flags(flags: &Value) -> Result<()> {
    let obj = match flags {
        Value::Object(m) => m,
        other => {
            return Err(Error::param(format!(
                "module_flags must be a dict, got {other:?}"
            )))
        }
    };
    let mut stack: Vec<(&Map<String, Value>, usize)> = vec![(obj, 0)];
    let mut nodes: usize = 0;
    while let Some((current, depth)) = stack.pop() {
        if depth > MAX_FLAG_DEPTH {
            return Err(Error::param(format!(
                "module_flags nesting depth exceeds the limit {MAX_FLAG_DEPTH}"
            )));
        }
        for (_key, value) in current.iter() {
            nodes += 1;
            if nodes > MAX_FLAG_NODES {
                return Err(Error::param(format!(
                    "module_flags node count exceeds the limit {MAX_FLAG_NODES}"
                )));
            }
            match value {
                Value::Object(m) => stack.push((m, depth + 1)),
                Value::Array(items) => {
                    for item in items {
                        nodes += 1;
                        if nodes > MAX_FLAG_NODES {
                            return Err(Error::param(format!(
                                "module_flags node count exceeds the limit {MAX_FLAG_NODES}"
                            )));
                        }
                        if let Value::Object(m) = item {
                            stack.push((m, depth + 1));
                        }
                        // All other types are legal scalars (the JSON value domain is inherently bounded)
                    }
                }
                // str/int/float/bool/null are all allowed types
                _ => {}
            }
        }
    }
    Ok(())
}

/// isostress protocol parameter set. Validated on construction (equivalent to Python `__post_init__`).
#[derive(Debug, Clone, PartialEq)]
pub struct Params {
    pub random_len: u64,
    pub random_rate: u64,
    pub window: u64,
    pub key_len: u64,
    pub hash_name: String,
    pub aead_name: String,
    pub module_flags: Value,
}

impl Params {
    pub fn new() -> Result<Self> {
        Self::build(
            RANDOM_LEN,
            RANDOM_RATE,
            WINDOW,
            KEY_LEN,
            HASH_NAME.to_string(),
            AEAD_NAME.to_string(),
            Value::Object(Map::new()),
        )
    }

    /// Full-field constructor (illegal values are rejected with [`Error::Param`]).
    pub fn build(
        random_len: u64,
        random_rate: u64,
        window: u64,
        key_len: u64,
        hash_name: String,
        aead_name: String,
        module_flags: Value,
    ) -> Result<Self> {
        let p = Params {
            random_len,
            random_rate,
            window,
            key_len,
            hash_name,
            aead_name,
            module_flags,
        };
        p.validate()?;
        Ok(p)
    }

    fn validate(&self) -> Result<()> {
        if self.random_len == 0 || !self.random_len.is_multiple_of(8) {
            return Err(Error::param(
                "random_len must be a positive integer and a multiple of 8",
            ));
        }
        if self.random_len / 8 > MAX_NONCE as u64 {
            return Err(Error::param(format!(
                "random_len/8 must not exceed the connection nonce cap {MAX_NONCE} bytes"
            )));
        }
        if !matches!(self.key_len, 128 | 192 | 256) {
            return Err(Error::param("key_len supports 128/192/256 only"));
        }
        if self.window == 0 {
            return Err(Error::param("window must be a positive integer"));
        }
        if self.random_rate == 0 {
            return Err(Error::param("random_rate must be a positive integer"));
        }
        validate_module_flags(&self.module_flags)?;
        Ok(())
    }

    /// On-the-wire key/value pairs of the parameter JSON (key order guaranteed by serde_json BTreeMap lexicographic order).
    /// Contains no version / protocol identifier fields — no version string appears anywhere in the on-the-wire data.
    fn to_wire(&self) -> Value {
        let mut m = Map::new();
        m.insert("random_len".into(), Value::from(self.random_len));
        m.insert("random_rate".into(), Value::from(self.random_rate));
        m.insert("window".into(), Value::from(self.window));
        m.insert("key_len".into(), Value::from(self.key_len));
        m.insert("hash".into(), Value::String(self.hash_name.clone()));
        m.insert("aead".into(), Value::String(self.aead_name.clone()));
        m.insert("module_flags".into(), self.module_flags.clone());
        Value::Object(m)
    }

    /// Compact JSON bytes (keys lexicographic, no whitespace, UTF-8). 120 bytes under default parameters.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let wire = self.to_wire();
        let s = serde_json::to_vec(&wire)
            .map_err(|e| Error::param(format!("parameter serialization failed: {e}")))?;
        if s.len() > MAX_PARAM_JSON {
            return Err(Error::param("parameter payload too large"));
        }
        Ok(s)
    }

    /// Build a parameter set from a peer JSON value. Peer-controllable input: all type/value errors are uniformly
    /// converged into [`Error::Param`]. Missing keys take the documented defaults; numeric fields accept integers / numeric strings
    /// (aligned with Python `int()` convergence behavior); hash/aead scalars are converted to strings for comparison.
    pub fn from_value(v: &Value) -> Result<Self> {
        let obj = match v {
            Value::Object(m) => m,
            _ => return Err(Error::param("peer parameter payload must be a JSON object")),
        };
        let flags = match obj.get("module_flags") {
            Some(f) => {
                if !f.is_object() {
                    return Err(Error::param("module_flags must be a dict"));
                }
                f.clone()
            }
            None => Value::Object(Map::new()),
        };
        let p = Params {
            random_len: coerce_u64(obj.get("random_len"), RANDOM_LEN, "random_len")?,
            random_rate: coerce_u64(obj.get("random_rate"), RANDOM_RATE, "random_rate")?,
            window: coerce_u64(obj.get("window"), WINDOW, "window")?,
            key_len: coerce_u64(obj.get("key_len"), KEY_LEN, "key_len")?,
            hash_name: coerce_string(obj.get("hash"), HASH_NAME)?,
            aead_name: coerce_string(obj.get("aead"), AEAD_NAME)?,
            module_flags: flags,
        };
        p.validate()
            .map_err(|e| Error::param(format!("peer parameters invalid: {}", plain(&e))))?;
        Ok(p)
    }

    /// Seven-item match check (F.1: fixed order; stop at the first mismatch).
    /// Returns the reason of the first mismatch; returns `None` when all are equal.
    pub fn match_error(&self, peer: &Params) -> Option<String> {
        if peer.random_len != self.random_len {
            return Some("random_len mismatch".into());
        }
        if peer.key_len != self.key_len {
            return Some("key_len mismatch".into());
        }
        if peer.window != self.window {
            return Some("window mismatch".into());
        }
        if peer.random_rate != self.random_rate {
            return Some("random_rate mismatch".into());
        }
        if peer.hash_name != self.hash_name {
            return Some("hash mismatch".into());
        }
        if peer.aead_name != self.aead_name {
            return Some("aead mismatch".into());
        }
        if peer.module_flags != self.module_flags {
            return Some("module_flags mismatch".into());
        }
        None
    }
}

impl Default for Params {
    fn default() -> Self {
        Params::new().expect("default parameters are always valid")
    }
}

/// Bare message with the Display prefix stripped (aligned with Python exception text style).
fn plain(e: &Error) -> String {
    match e {
        Error::Param(m)
        | Error::Security(m)
        | Error::Protocol(m)
        | Error::Crypto(m)
        | Error::Timeout(m)
        | Error::SilentDrop(m)
        | Error::Session(m) => m.clone(),
        Error::Io(e2) => e2.to_string(),
    }
}

/// Numeric field convergence: integer / float truncation / bool / decimal string -> u64; anything else is Param.
/// Aligned with Python `int()` semantics (floats truncated toward zero; strings parsed as decimal).
fn coerce_u64(v: Option<&Value>, default: u64, field: &str) -> Result<u64> {
    let out = match v {
        None => default,
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_u64() {
                i
            } else if let Some(i) = n.as_i64() {
                if i < 0 {
                    return Err(Error::param(format!("{field} must be a positive integer")));
                }
                i as u64
            } else if let Some(f) = n.as_f64() {
                if !(f.is_finite()) || f < 0.0 {
                    return Err(Error::param(format!("{field} must be a positive integer")));
                }
                f as u64
            } else {
                return Err(Error::param(format!("{field} is not a valid number")));
            }
        }
        Some(Value::Bool(b)) => {
            if *b {
                1
            } else {
                0
            }
        }
        Some(Value::String(s)) => {
            let t = s.trim();
            if let Ok(i) = t.parse::<u64>() {
                i
            } else if let Ok(f) = t.parse::<f64>() {
                if f.is_finite() && f >= 0.0 {
                    f as u64
                } else {
                    return Err(Error::param(format!("{field} must be a positive integer")));
                }
            } else {
                return Err(Error::param(format!("{field} must be an integer")));
            }
        }
        Some(_) => return Err(Error::param(format!("{field} has an invalid type"))),
    };
    Ok(out)
}

/// String field convergence: strings pass through unchanged; numbers / bools are converted to strings for comparison (a
/// non-string value will ultimately mismatch in the seven-item check — the final outcome matches Python's `str()` convergence path).
fn coerce_string(v: Option<&Value>, default: &str) -> Result<String> {
    match v {
        None => Ok(default.to_string()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Number(n)) => Ok(n.to_string()),
        Some(Value::Bool(b)) => Ok(b.to_string()),
        Some(_) => Err(Error::param("invalid value type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guide_defaults_and_wire_json() {
        let p = Params::new().unwrap();
        assert_eq!(
            (
                p.random_len,
                p.random_rate,
                p.window,
                p.key_len,
                p.hash_name.as_str(),
                p.aead_name.as_str()
            ),
            (256, 1024, 60, 256, "SHA3-256", "AES-256-GCM")
        );
        // F.1: under default parameters the parameter JSON is exactly 120 bytes, byte-for-byte equal to the specified layout
        let expected: &[u8] = br#"{"aead":"AES-256-GCM","hash":"SHA3-256","key_len":256,"module_flags":{},"random_len":256,"random_rate":1024,"window":60}"#;
        let got = p.to_json().unwrap();
        assert_eq!(got, expected);
        assert_eq!(got.len(), 120);
    }

    #[test]
    fn bad_values_fail() {
        assert!(Params::build(
            255,
            1024,
            60,
            256,
            "SHA3-256".into(),
            "AES-256-GCM".into(),
            Value::Object(Map::new())
        )
        .is_err()); // not a multiple of 8
        assert!(Params::build(
            4608,
            1024,
            60,
            256,
            "SHA3-256".into(),
            "AES-256-GCM".into(),
            Value::Object(Map::new())
        )
        .is_err()); // exceeds the nonce cap
        assert!(Params::build(
            256,
            1024,
            60,
            100,
            "SHA3-256".into(),
            "AES-256-GCM".into(),
            Value::Object(Map::new())
        )
        .is_err()); // bad key_len
        assert!(Params::build(
            256,
            1024,
            0,
            256,
            "SHA3-256".into(),
            "AES-256-GCM".into(),
            Value::Object(Map::new())
        )
        .is_err()); // zero window
        assert!(Params::build(
            256,
            0,
            60,
            256,
            "SHA3-256".into(),
            "AES-256-GCM".into(),
            Value::Object(Map::new())
        )
        .is_err()); // zero rate
    }

    #[test]
    fn deep_and_wide_flags_fail() {
        // Nesting depth > 32 is rejected (explicit stack iteration, no stack overflow): 33 dict layers wrapped from the inside out
        let deep = {
            let mut inner = Value::Object(Map::new());
            for i in 0..33 {
                let mut m = Map::new();
                m.insert(format!("node{i}"), inner);
                inner = Value::Object(m);
            }
            inner
        };
        let mut root = Map::new();
        root.insert("deep".into(), deep);
        assert!(Params::build(
            256,
            1024,
            60,
            256,
            "SHA3-256".into(),
            "AES-256-GCM".into(),
            Value::Object(root)
        )
        .is_err());

        // Total node count > 1024 is rejected
        let mut wide = Map::new();
        for i in 0..1025 {
            wide.insert(format!("k{i}"), Value::from(i));
        }
        assert!(Params::build(
            256,
            1024,
            60,
            256,
            "SHA3-256".into(),
            "AES-256-GCM".into(),
            Value::Object(wide)
        )
        .is_err());
    }

    #[test]
    fn from_wire_converges_errors() {
        // Peer-controllable input: all type/value errors converge to Param
        for bad in ["[1,2]", "42", "null", "\"str\""] {
            let v: Value = serde_json::from_str(bad).unwrap();
            assert!(Params::from_value(&v).is_err(), "should reject {bad}");
        }
        let v: Value = serde_json::from_str(r#"{"random_len": "not-an-int"}"#).unwrap();
        assert!(Params::from_value(&v).is_err());
        let v: Value = serde_json::from_str(r#"{"key_len": 999}"#).unwrap();
        assert!(Params::from_value(&v).is_err());
        // Out-of-range numbers (1e999) are rejected by the JSON parser itself;
        // the float branch of coerce_u64 refuses non-finite values as a second
        // guard. Peer-controlled overflow has no path to a panic here.
        assert!(serde_json::from_str::<Value>(r#"{"random_len": 1e999}"#).is_err());
        // Numeric string convergence (aligned with Python int() behavior)
        let v: Value = serde_json::from_str(r#"{"random_len": "512", "window": 45}"#).unwrap();
        let ok = Params::from_value(&v).unwrap();
        assert_eq!(ok.random_len, 512);
        assert_eq!(ok.window, 45);
    }

    #[test]
    fn match_fixed_order() {
        let a = Params::new().unwrap();
        let b = Params::new().unwrap();
        assert_eq!(a.match_error(&b), None);
        // When several items are changed at once, only the first is reported (fixed order: random_len takes priority)
        let c = Params::build(
            512,
            1024,
            30,
            128,
            "SHA3-256".into(),
            "AES-256-GCM".into(),
            Value::Object(Map::new()),
        )
        .unwrap();
        assert_eq!(a.match_error(&c).as_deref(), Some("random_len mismatch"));
        let d = Params::build(
            256,
            1024,
            30,
            128,
            "SHA3-256".into(),
            "AES-256-GCM".into(),
            Value::Object(Map::new()),
        )
        .unwrap();
        assert_eq!(a.match_error(&d).as_deref(), Some("key_len mismatch"));
        let mut flags = Map::new();
        flags.insert("x".into(), Value::from(1));
        let e = Params::build(
            256,
            1024,
            60,
            256,
            "SHA3-256".into(),
            "AES-256-GCM".into(),
            Value::Object(flags),
        )
        .unwrap();
        assert_eq!(a.match_error(&e).as_deref(), Some("module_flags mismatch"));
    }
}
