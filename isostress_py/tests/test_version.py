# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""Version contract tests (total-guide / client / server versions; see the "Naming Rules" section of the root README)."""

from datetime import datetime, timedelta, timezone

import pytest

from isostress_py.version import (
    APPLIES_TO_DOC_VERSIONS,
    BUILD_DATE,
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
    implementation_identifier,
)


def test_docs_version_declaration() -> None:
    # document version: the specification text's own revision; it does not take part in network communication
    assert DOCS_VERSION == "1.0.0"


def test_implementation_id_is_a_client_version() -> None:
    # this repository is the client implementation; `PY` is its prefix.
    # The compatibility list holds the release form; the build identifier adds the date segment.
    assert LANGUAGE_PREFIX == "PY"
    assert CODE_VERSION == "1.0.0"
    assert BUILD_DATE == "20261030"
    assert IMPLEMENTATION_ID == "ISOSTRESS_PY-1.0.0-20261030"
    assert implementation_identifier("PY", CODE_VERSION, "") == "ISOSTRESS_PY-1.0.0"


def test_role_declaration() -> None:
    assert ROLE == "client"


def test_client_versions_include_self() -> None:
    # every client version of this kind, and this implementation's release form must be one of them
    assert CLIENT_VERSIONS == ("ISOSTRESS_PY-1.0.0", "ISOSTRESS_RS-1.0.0")
    assert implementation_identifier("PY", CODE_VERSION, "") in CLIENT_VERSIONS


def test_server_versions_declared_separately() -> None:
    # server versions are a separate carrier, not folded into the client list
    assert SERVER_VERSIONS == ("ISOSTRESS_SV-1.0.0",)
    assert IMPLEMENTATION_ID not in SERVER_VERSIONS


def test_applies_to_is_many_to_many() -> None:
    # a tuple, because one implementation may apply to several total-guide versions,
    # and several implementations may apply to one total-guide version
    assert isinstance(APPLIES_TO_DOC_VERSIONS, tuple)
    assert APPLIES_TO_DOC_VERSIONS == ("1.0.0",)
    assert DOCS_VERSION in APPLIES_TO_DOC_VERSIONS


def test_follows_doc_declaration() -> None:
    # Bidirectional declaration on the code side: which document this implementation applies to
    assert FOLLOWS_DOC == "isostress Protocol Master Guide"
    assert FOLLOWS_DOC_PATH == "isostress-docs/en/spec/isostress-1.0.0-Master_Guide.md"


def test_no_protocol_identifier_constant() -> None:
    # Online frames carry no protocol identifier constant: this constant should not exist in the version module
    import isostress_py.version as version_module

    assert not hasattr(version_module, "PROTOCOL_VERSION")
    assert not hasattr(version_module, "PROTOCOL_IDENTIFIER_BYTES")


def test_format_version_contract() -> None:
    # Two segments: this implementation's client/server version identifier, then the total-guide version
    assert format_version() == "ISOSTRESS_PY-1.0.0-20261030 (docs 1.0.0)"


def test_build_date_is_set_for_a_development_build() -> None:
    # A development build carries the date segment; the release form stays available for the compatibility lists
    assert BUILD_DATE == "20261030"
    assert implementation_identifier("PY", "1.0.0", "") == "ISOSTRESS_PY-1.0.0"
    assert IMPLEMENTATION_ID == "ISOSTRESS_PY-1.0.0-20261030"


def test_build_date_appends_eight_digit_date() -> None:
    assert (
        implementation_identifier("PY", "1.0.0", "20261030")
        == "ISOSTRESS_PY-1.0.0-20261030"
    )


def test_build_date_rejects_other_shapes() -> None:
    # Anything that is not YYYYMMDD fails at composition time, not in a published identifier
    for bad in ("2026-10-24", "2026102", "20261332x", "   "):
        with pytest.raises(ValueError):
            implementation_identifier("PY", "1.0.0", bad)


def test_build_date_does_not_run_ahead_of_the_clock() -> None:
    # BUILD_DATE is maintained by hand at commit time. Pinning it to HEAD fails on
    # the merge commit, whose date is the merge day; require a real calendar date
    # that is not in the future, with one day of timezone slack.
    if not BUILD_DATE:
        return
    datetime.strptime(BUILD_DATE, "%Y%m%d")
    latest = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y%m%d")
    assert BUILD_DATE <= latest
