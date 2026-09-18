"""Repo-root pytest bootstrap.

This project uses a ``src/`` layout (``src/qwed_new``). When the package is
not installed in editable mode, the interpreter would otherwise import the
stale copy from site-packages instead of the working tree, silently testing
old code. Prepending ``src/`` makes local test runs always exercise the
current source. This is a no-op when the package is installed editable.
"""

import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)
