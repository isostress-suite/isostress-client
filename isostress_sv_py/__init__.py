# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""isostress server role.

The implementation lives in one module, isostress_sv_py.server.  The version
contract lives in isostress_sv_py.version and is deliberately separate, because
the contract is a declaration about the outside world while the server is the
implementation of it.
"""

from .version import (
    CODE_VERSION,
    DOCS_NAME,
    DOCS_PATH,
    DOCS_VERSIONS,
    DOCUMENT_REVISION,
    IMPLEMENTATION_ID,
    PROGRAM_NAME,
    ROLE,
    format_version,
)

__all__ = [
    "CODE_VERSION",
    "DOCS_NAME",
    "DOCS_PATH",
    "DOCS_VERSIONS",
    "DOCUMENT_REVISION",
    "IMPLEMENTATION_ID",
    "PROGRAM_NAME",
    "ROLE",
    "format_version",
]
