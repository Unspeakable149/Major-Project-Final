"""Pytest bootstrap: put scripts/ on sys.path so tests can `import rules`,
`import scoring`, etc. directly, matching how pcap_engine.py itself imports
them (sys.path.insert, not package-relative imports).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "scripts"))
