# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 isostress Suite maintainers

"""``python -m isostress_py`` entry point.

Absolute import on purpose: PyInstaller collects this file as a top-level script, where a
relative import fails with "attempted relative import with no known parent package"
(release.yml exe job, 2026-10-11).
"""

from isostress_py.cli import main

if __name__ == "__main__":
    main()
