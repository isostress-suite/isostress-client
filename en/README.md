# isostress

## 这里有什么

The English implementation notes and Rust details.

## 按什么找

Build and verification steps are in the [DEV-GUIDE](https://github.com/isostress-suite/isostress-docs/blob/main/en/DEV-GUIDE.md).

**isostress (ISTS)** — development languages **Python and Rust**; reference implementations **ISOSTRESS_PY-1.0.0-20261030** and **ISOSTRESS_RS-1.0.0-20261030** (client version **1.0.0**) | conforms to "isostress Protocol Master Guide" (**docs 1.0.0**)

An open, zero trust, end-to-end encrypted communication protocol with Python and Rust reference implementations. Built on **PSK + X25519 + AES-256-GCM + per-packet ratchet**, providing a four-phase handshake and full-duplex encrypted communication.

- Protocol is public, implementation is free, parameters are self-governing, silent drop
- End-to-end encryption: no relay node can decrypt the communication content
- Forward secrecy: X25519 ephemeral keys + per-packet ratchet rotation (consume state before sending)
- No reliance on a centralized trust anchor; the token hash (out-of-band exchange) is shared out-of-band

## Correspondence Between Documentation and Code

This implementation conforms to "isostress Protocol Master Guide"; the path is given by FOLLOWS_DOC_PATH in isostress_py/version.py:

```
isostress-docs/en/spec/isostress-1.0.0-Master_Guide.md
```

Documentation and code are **not bound by version numbers**: the document side declares "which settings of the code this document governs", and the code side declares "which document this implementation follows".
**Handshake frames carry no version string** — neither the phase 1 parameter JSON nor the phase 4 AAD contains any version or protocol identifier field.

## Directory Layout

```
├── isostress_py/                  Python reference implementation (program ID ISOSTRESS_PY-1.0.0-20261030)
│   ├── version.py             single source of truth for the version contract (document version / client version / applicability / followed document)
│   ├── errors.py              protocol exception hierarchy (Master Guide Appendix H.5)
│   ├── params.py              parameter set and validation (Appendix F.1: fixed seven-item order matching)
│   ├── identity.py            P2P placeholder token hash (4.1.1)
│   ├── crypto.py              X25519 / HKDF-SHA3-256 / HMAC / AES-256-GCM
│   ├── frames.py              four kinds of on-wire frame codec + overall deadline reading (Appendix F)
│   ├── handshake.py           four-phase handshake state machine (Appendix H.1/H.2)
│   ├── session.py             encrypted session: ratchet/replay/padding/time window (Appendix F.5/G)
│   ├── transport.py           listener/connector runner + heartbeat chat session (Appendix H.3/H.6)
│   ├── cli.py                 minimal command line
│   └── tests/                 pytest suite (primitives/frames/handshake/session/end-to-end)
├── isostress_rs/               Rust reference implementation (program ID ISOSTRESS_RS-1.0.0-20261030; flat single-bin crate)
├── isostress_sv_py/            Python server implementation (program ID ISOSTRESS_SV-1.0.0-20261030)
│   ├── version.py           version contract (server role, role prefix SV)
│   ├── server.py            pairing, byte relay and the L4 control plane (one file)
│   ├── CONFORMANCE.md       protocol conformance checklist (with two open questions)
│   └── tests/               pytest suite
├── LICENSE
└── README.md
```

## Quick Start

### Dependencies

- Python >= 3.10 (64-bit recommended on Windows)
- pip install cryptography

### Install and Run

```bash
cd isostress_py
pip install .                     # or pip install -e .
python -m isostress_py --version
# → ISOSTRESS_PY-1.0.0-20261030 (docs 1.0.0)

# Listening side (responder)
isostress-py --role listen --port 37291 --psk-file psk.txt

# Connecting side (initiator)
isostress-py --role connect --host <peer IP> --port 37291 --psk-file psk.txt

# Environment variable approach (recommended for scripts)
set ISOSTRESS_PSK=<64-digit hex>          # Windows
export ISOSTRESS_PSK=<64-digit hex>       # Linux/macOS
isostress-py --role listen --port 37291 --psk-env
```

**Running with no arguments starts the interactive wizard** (recommended for beginners): it asks in turn for the role, address and port, the PSK (pressing Enter generates a fresh PSK and prints it for the peer) and the protocol parameters, with Enter accepting the default at every step. When stdin or stdout is redirected (pipe, CI, IDE), no-argument startup prints usage and exits 0 instead of blocking.

Inside a session, type a message and press Enter to send; exit with /quit or Ctrl+C. For a two-instance demo on the local machine, open a second terminal and run the opposite role with the same PSK and parameters.

### Main Parameters

| Parameter | Default | Description |
|------|--------|------|
| --port | 37291 | port number |
| --random-len | 256 | access random value length (bits, multiple of 8) |
| --random-rate | 1024 | random value generation rate (operations/sec) |
| --window | 60 | negotiated window (seconds, **must be identical on both sides**) |
| --time-window | 30 | timestamp window (seconds, configurable per peer) |
| --padding-min/max | off | random padding range (0–2048B, may be enabled on one side only) |
| --jitter | 0 | send timing jitter (seconds) |
| --retry-count / --retry-interval | 3 / 5.0 | connection retries (initiator only) |
| --silent-hold | 15.0 | strict silent hold duration in seconds (listen side waits silently early in the handshake) |

### Tests

```bash
python -m pytest isostress_py/tests -q      # run from the repository root
```

Coverage: version contract, derivation formulas (MK/EK/SID/nonce byte-for-byte against the Master Guide), parameter validation,
pre-checks for frame limits, Slowloris overall deadline, two-sided handshake, PSK errors, low-order point silent drop,
rejection of replay/tampering, ratchet forward roll beyond the window, one-sided padding interop, heartbeat 165B size assertions,
and a real two-sided TCP flow.

## Security Highlights

- **PSK is the root trust anchor**: a leaked PSK = total compromise. It must be exactly 32 bytes of high-entropy random data
  (64-digit hex / Base64), injected via --psk-file (0600) or --psk-env;
  the client rejects public default values and low-entropy keys.
- **Out-of-band exchange of the token hash**: the token hash must be shared in advance over a secure channel; the protocol does not "discover" the peer.
- The ratchet is unidirectional (HKDF chained derivation) with no DH self-healing; a failed send desynchronizes the session irreversibly,
  and reconnection is mandatory (by design, see Master Guide Appendix H.4).
- The responder performs **strict silent drop** on every handshake-phase failure (sends no bytes, does not close proactively,
  swallows bytes while pending, diagnostics go to local stderr only).

## Version Notes

| Item | Value |
|----|----|
| applicable document version | 1.0.0 |
| client version | ISOSTRESS_PY-1.0.0-20261030 (Python in this repository), ISOSTRESS_RS-1.0.0-20261030 (Rust in this repository) |
| server version | ISOSTRESS_SV-1.0.0-20261030 (`isostress_sv_py/` in this repository) |
| program ID | ISOSTRESS_PY-1.0.0-20261030 (prefix PY) |
| followed document | "isostress Protocol Master Guide", path isostress-docs/en/spec/isostress-1.0.0-Master_Guide.md |

### Naming Convention System (docs / code · required reading for takeover / fork)

**This project has three kinds of version number** — document version, client version, server version; handshake frames carry no version string, so peer compatibility is not judged by version numbers.

#### document version (docs version)

| Item | Rule |
|----|------|
| format | 1.0.x (major.minor.revision) |
| carrier | the Master Guide document (`en/spec/isostress-1.0.0-Master_Guide.md` in the standalone document repository `isostress-docs`) |
| current value | `1.0.0` |
| revision digit increment | clarifications, errata, readability improvements — no change to any on-wire behavior definition |
| minor digit increment | new appendix or optional section — no change to on-wire behavior definitions |
| major digit increment | restatement of core protocol semantics (usually coupled with a client/server version increment) |
| participates in network communication | No (pure document number) |

#### client version and server version

| Item | Rule |
|----|------|
| format | `isostress_<prefix>-<major.minor.revision>`, e.g. `ISOSTRESS_PY-1.0.0` (client) / `ISOSTRESS_SV-1.0.0` (server) |
| date segment | a development build appends `-YYYYMMDD`, the commit date (UTC+8), to the version; release candidates and releases drop it, and both use the same identifier; package metadata keeps a numeric-only version |
| carrier | two kinds: **client versions** (`isostress_<language prefix>-<major.minor.revision>`) and **server versions** (`ISOSTRESS_SV-<major.minor.revision>`); an implementation concretizes the specification but does not share its version number |
| current value | ISOSTRESS_PY-1.0.0-20261030 and ISOSTRESS_RS-1.0.0-20261030; server ISOSTRESS_SV-1.0.0-20261030 |
| language prefix table | PY=Python, GO=Go, RS=Rust, C=C++ (**not the C language or C#**, which must define their own prefixes), JS=JavaScript/TypeScript, JVM=Java/Kotlin; other languages define their own all-caps prefix, which must be unique across the repository |
| revision digit increment | bug fixes, security hardening — on-wire byte format **unchanged** |
| minor digit increment | new optional capability (e.g. a new hook, a padding strategy) — on-wire format unchanged or backward-compatible addition only |
| major digit increment | change to the on-wire byte format (frame layout / derivation formula) — old and new implementations are by design not interoperable (handshake will necessarily fail) |
| multi-language coexistence | implementations in different languages **may share the same version number** (ISOSTRESS_PY-1.0.0 and isostress_GO-1.0.0 coexist), distinguished by the language prefix |
| participates in network communication | No (the version number itself does not participate; handshake frames carry no version string) |
| other-language implementations | the development languages are Python and Rust; to add another language, create a sibling directory named after its program ID (for example isostress_go/), alongside isostress_py/ and isostress_rs/, with a protocol conformance checklist attached |
| server implementations | a server implementation is named after its program ID as well (isostress_sv_py/) and carries a protocol conformance checklist; a server never decrypts, it only pairs and relays bytes |
| merge / recording suggestions | when merging a fork, when a maintainer creates a new branch, or when promoting a standalone implementation to the mainline, the core recommendation is: **collect all code into a single file** (one implementation per file, no new directory trees added to the mainline directory), with a protocol conformance checklist attached |

#### Applicability (many-to-many)

The relation between a document version and the client/server versions is **not** one-to-one; it is many-to-many:

| Relation | Rule |
|----------|------|
| one document version -> several implementation versions | several implementations of the same kind whose protocol behaviour has not changed **share one declaration**; no rewrite is needed per version |
| several document versions -> one implementation version | one implementation may apply to several guides at once; listed item by item in `APPLIES_TO_DOC_VERSIONS` |
| same number, different implementation | identical version numbers do **not** mean the same implementation and do not constitute a compatibility claim |
| how compatibility is decided | applicability is a **declaration**, not a test; real compatibility is shown by the phase-three confirmation-label check |

So adding a Python patch release (`ISOSTRESS_PY-1.0.0`, unchanged protocol behaviour) requires **no change** to this section; when the Master Guide moves to a new version, simply append it to the applicable list on the implementation side.

#### Bidirectional Documentation–Code Declaration

Since handshake frames carry no version string, peer compatibility is not judged by version numbers. The correspondence between documentation and code is maintained by **bidirectional declarations**:

- **Documentation side**: the header of spec/isostress-1.0.0-Master_Guide.md declares "this document defines the protocol behavior and tunable parameters on the code side".
- **Code side**: FOLLOWS_DOC / FOLLOWS_DOC_PATH in isostress_py/version.py declare which document this implementation follows.

If the two ends follow inconsistent specifications, the handshake fails at the **phase 3 confirmation label**.

#### Display and Citation Conventions

- **Citing an implementation**: use its full version identifier (client or server), e.g. `ISOSTRESS_PY-1.0.0`; do not append the document version
- **--version output** (the two parts, in order): implementation version identifier, document version → ISOSTRESS_PY-1.0.0-20261030 (docs 1.0.0)
- **Citing protocol behavior**: write "for protocol behavior see section X of the isostress Protocol Master Guide"; do not cite a version string
- **Prohibitions**: ① mixing the docs version into the program ID; ② writing any version string into handshake frames; ③ reusing any version number ever used; ④ a discontinuous renumbering of an already-published version; ⑤ hardcoding any version string outside version.py

#### Single Source of Truth and Change Process

- isostress_py/version.py is the **single source of truth**: DOCS_VERSION, CODE_VERSION / LANGUAGE_PREFIX / IMPLEMENTATION_ID, FOLLOWS_DOC / FOLLOWS_DOC_PATH
- isostress_py/tests/test_version.py locks the contract — a version change must update the test together with it; if the test is not updated, the commit is blocked
- Complete checklist for a version change: version.py → test_version.py → the corresponding table in this section → pyproject.toml (version = CODE_VERSION) → version references in the relevant documents

## License

**AGPL-3.0-or-later**, or a **commercial license** by separate arrangement. See [LICENSING.md](../LICENSING.md) and [LICENSE](../LICENSE). The protocol specification is permanently open source.
