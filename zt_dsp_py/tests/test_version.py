# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 ZT-DSP Suite maintainers (copyright holder: SCAL-ROAM)

"""Version contract tests (total-guide / client / server versions; see the "Naming Rules" section of the root README)."""

from zt_dsp_py.version import (
    CLIENT_VERSIONS,
    CODE_VERSION,
    DOCS_VERSION,
    FOLLOWS_DOC,
    FOLLOWS_DOC_PATH,
    IMPLEMENTATION_ID,
    LANGUAGE_PREFIX,
    ROLE,
    SERVER_VERSIONS,
    format_version,
)


def test_docs_version_declaration() -> None:
    # document version: the specification text's own revision; it does not take part in network communication
    assert DOCS_VERSION == "1.0.2"


def test_implementation_id_is_a_client_version() -> None:
    # this repository is the client implementation; `PY` is its prefix
    assert LANGUAGE_PREFIX == "PY"
    assert CODE_VERSION == "1.0.0"
    assert IMPLEMENTATION_ID == "ZT-DSP_PY-1.0.0"
    assert IMPLEMENTATION_ID.endswith(f"-{CODE_VERSION}")


def test_role_declaration() -> None:
    assert ROLE == "client"


def test_client_versions_include_self() -> None:
    # every client version of this kind, and this implementation must be one of them
    assert CLIENT_VERSIONS == ("ZT-DSP_PY-1.0.0", "ZT-DSP_RS-1.0.0")
    assert IMPLEMENTATION_ID in CLIENT_VERSIONS


def test_server_versions_declared_separately() -> None:
    # server versions are a separate carrier, not folded into the client list
    assert SERVER_VERSIONS == ("ZT-DSP_SV-1.0.0",)
    assert IMPLEMENTATION_ID not in SERVER_VERSIONS


def test_no_doc_applicability_constant() -> None:
    # applicability is declared on the doc side; the code side carries no
    # applicability constant (removed; see CHANGELOG "Removed")
    import zt_dsp_py.version as version_module

    assert not hasattr(version_module, "APPLIES_TO_DOC_VERSIONS")


def test_follows_doc_declaration() -> None:
    # Bidirectional declaration on the code side: which document this implementation applies to
    assert FOLLOWS_DOC == "ZT-DSP Protocol Master Guide"
    assert FOLLOWS_DOC_PATH == "ZT-DSP-docs/en/spec/ZT-DSP-1.0.2-Master_Guide.md"


def test_no_protocol_identifier_constant() -> None:
    # Online frames carry no protocol identifier constant: this constant should not exist in the version module
    import zt_dsp_py.version as version_module

    assert not hasattr(version_module, "PROTOCOL_VERSION")
    assert not hasattr(version_module, "PROTOCOL_IDENTIFIER_BYTES")


def test_format_version_contract() -> None:
    # Two segments: this implementation's client/server version identifier, then the total-guide version
    assert format_version() == "ZT-DSP_PY-1.0.0 (docs 1.0.2)"
