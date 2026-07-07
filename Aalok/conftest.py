"""Pytest bootstrap: put Dashboard/ on sys.path so tests can `import live_backend`.

Chosen over adding Dashboard/__init__.py because the package shape would force
all internal imports (e.g. `import notifier`) to become `from Dashboard import ...`,
which would break the existing scripts that run from inside Dashboard/.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "Dashboard"))
