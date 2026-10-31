# isostress_sv_py

The isostress **server** role, in Python.

The server pairs peers and relays opaque bytes between them. It never
decrypts anything and it never inserts anything of its own into the wire
format.

Two things in the master guide are open to interpretation; both are written
down in `CONFORMANCE.md` under "待澄清", with the reasoning and the
question that has to be answered by the documentation owner:

1. the Phase 1 exchange order versus a server that pairs by identity;
2. the one derivation label in the shared vectors that does not follow the
   `-v3` suffix convention.

## Run it

```sh
python -m isostress_sv_py --profile beginner --listen 127.0.0.1:9931
```

The L4 control plane is off unless you ask for it, and refuses to start
without a token:

```sh
python -m isostress_sv_py --control 127.0.0.1:9932 --control-token ./token
```

## 这里有什么

| file | what |
|---|---|
| `server.py` | the whole implementation |
| `version.py` | the version contract |
| `CONFORMANCE.md` | the protocol conformance checklist |
| `tests/` | the test suite |

## 按什么找

- Behaviour lives in `server.py`; the identifier and its declarations live in `version.py`.
- The two open questions and their reasoning are in `CONFORMANCE.md`.
- Run the suite from the repository root: `python -m pytest isostress_sv_py/tests -q`.

## Tests

From the repository root, not from inside the package:

```sh
python -m pytest isostress_sv_py/tests -q
```

## Notes on the wire format

* The relay is byte-exact. A Phase 1 frame is replayed verbatim, because the
  raw bytes enter the Phase 3 transcript and a canonicalised re-encoding
  would make the confirmation tag mismatch.
* Every rejection path ends in the same silent drop with the same window, so
  a rejected peer cannot tell one reason from another by timing.
* Pairing is mutual: a peer is only connected to the peer whose identity is
  the exact inverse of its own.
* The identity directory is off in every profile. It would record when a
  token hash appeared, which is pairing metadata, and the specification
  forbids recording pairing metadata.
