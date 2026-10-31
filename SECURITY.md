# Security Policy

isostress is a security protocol; reports about the protocol, the Master Guide, or any
implementation here are welcome and treated seriously.

## Supported versions

| Version | Supported |
|---|---|
| code 1.0.x (this repository), following docs 1.0.0 | yes |
| earlier revisions | no |

## Reporting a vulnerability

Preferred channel: **GitHub private vulnerability reporting** ("Security" tab -> "Report a
vulnerability"). It keeps the report private, gives a shared
workspace for a fix, and produces an advisory that can be published with credit.

If private reporting is unavailable, open a minimal issue that asks for a private channel
**without including exploit details**, and the maintainer will respond with one.

Please include: affected version and file(s); whether the issue is in the protocol text, the
Python reference implementation, or the Rust reference implementation; a reproduction or a
precise argument; and the impact you believe it has. Do not include working exploit code in a
public issue.

## Scope notes

- Cryptography is delegated to `cryptography` (Python) and the RustCrypto crates; a flaw in
  those libraries belongs upstream, but tell us if this project uses them incorrectly.
- Both reference implementations (`isostress_py/` in Python and `isostress_rs/` in Rust) are supported
  and are expected to interoperate byte for byte. Reports against either are welcome.
- Denial of service by injecting a packet that terminates an established session is a **known,
  deliberate** fail-closed tradeoff. Report it only if you
  have a countermeasure that preserves the nonce guarantees.

## Secrets in history

No credentials belong in this repository, and the history was rebuilt to remove those that had
been committed once. Do not open a pull request containing a key, password or private path --
even a test one. The literal `FORBIDDEN_DEFAULT_PSK` in `cli.py` / `cli.rs` is a **denylist
constant** that the program refuses to start with; it is not a credential and must not be
removed.
