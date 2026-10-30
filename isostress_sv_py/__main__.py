# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""Entry point: python -m isostress_sv_py"""

import sys

from .server import main

if __name__ == "__main__":
    sys.exit(main())
