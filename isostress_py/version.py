# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""Version contract (single source of truth).

This project does not use a single abstract "code version". It has **three kinds of
versioned carrier**, and the relation between them is many-to-many:

total-guide version (docs version)
    The revision number of the Master Guide itself, written as `docs 1.0.0`.
    Used only for the revision counting of the document; it takes no part in network communication.

client version
    A client-side implementation, identified as `ISOSTRESS_<prefix>-<major.minor.revision>`,
    for example `ISOSTRESS_PY-1.0.0` (Python) or `ISOSTRESS_RS-1.0.0` (Rust).

server version
    A server-side implementation, identified the same way, for example `ISOSTRESS_SV-1.0.0`
    (repository `isostress-server`, currently a placeholder with no implementation yet).

Applicability (many-to-many)
    Several client/server versions may apply to the **same** total-guide version: a family of
    implementations of the same kind whose protocol behaviour has not changed needs no new
    declaration. Conversely, **one** total-guide version may apply to several client and
    server versions at once. Compatibility is therefore never expressed by equality of version
    numbers, only by the declarations below.

The correspondence between documentation and code is maintained via a **bidirectional declaration**, not bound by version numbers:

    - Doc side: each document's header declares "which implementations this document applies to"
    - Code side: declares "which documents this implementation applies to" -- see the
      FOLLOWS_DOC / FOLLOWS_DOC_PATH / APPLIES_TO_DOC_VERSIONS constants below

Handshake frames **carry no protocol-identifier constants**: the Phase 1 parameter JSON and the Phase 4 AAD
contain no version string. Whether the peer is compatible is reflected by the Phase 3 confirmation-label check.

Hard-coding version strings anywhere is forbidden; this module is the single source of truth.
"""

# --- Code-side bidirectional declaration: which document this implementation applies to ---
# NOTE: this path points into the SIBLING repository isostress-docs.
# It does NOT resolve inside this repo -- this repo ships no copy of the protocol text.
# Once published, read it from the isostress-docs repository on GitHub.
FOLLOWS_DOC: str = "isostress Protocol Master Guide"
FOLLOWS_DOC_PATH: str = "isostress-docs/en/spec/isostress-1.0.0-Master_Guide.md"

# --- Total-guide versions this implementation applies to (many-to-many: may hold several) ---
APPLIES_TO_DOC_VERSIONS: tuple[str, ...] = ("1.0.0",)

# --- total-guide version (document revision number; takes no part in network communication) ---
DOCS_VERSION: str = "1.0.0"

# --- Role of this implementation: "client" or "server" ---
ROLE: str = "client"

# --- language prefix; `SV` is a role prefix (server) rather than a language one ---
LANGUAGE_PREFIX: str = "PY"

# --- implementation version: the numeric part of a client / server version ---
CODE_VERSION: str = "1.0.0"

# --- build date segment: development builds carry `-YYYYMMDD`; RC and release leave it empty ---
# Value is the commit date in UTC+8. Development builds carry the date segment;
# release candidates and releases leave it empty, so the published identifier
# keeps its numeric form.
BUILD_DATE: str = "20261030"


def implementation_identifier(
    prefix: str, code_version: str, build_date: str = ""
) -> str:
    """Compose `ISOSTRESS_<prefix>-<version>[-<YYYYMMDD>]`.

    An empty build date yields the release identifier. A non-empty one must be eight
    digits. A malformed date raises ValueError here rather than producing a published
    identifier: composition fails fast, and the Rust twin panics for the same input.
    """
    if not build_date:
        return f"ISOSTRESS_{prefix}-{code_version}"
    if len(build_date) != 8 or not build_date.isdigit():
        raise ValueError("BUILD_DATE must be YYYYMMDD or empty")
    return f"ISOSTRESS_{prefix}-{code_version}-{build_date}"


IMPLEMENTATION_ID: str = implementation_identifier(
    LANGUAGE_PREFIX, CODE_VERSION, BUILD_DATE
)

# --- All client versions of this kind, applicable to the same total-guide versions ---
CLIENT_VERSIONS: tuple[str, ...] = ("ISOSTRESS_PY-1.0.0", "ISOSTRESS_RS-1.0.0")

# --- Server versions applicable to the same total-guide versions (placeholder, not implemented) ---
SERVER_VERSIONS: tuple[str, ...] = ("ISOSTRESS_SV-1.0.0",)


def format_version() -> str:
    """The single-line version string for the CLI --version output.

    In order: this implementation's client/server version identifier, then the total-guide version.
    """
    return f"{IMPLEMENTATION_ID} (docs {DOCS_VERSION})"
