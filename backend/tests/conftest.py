import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# Isolate the test suite from the demo database: point SQLAlchemy at a
# throwaway SQLite file BEFORE any backend.app.* module is imported.
# Without this, persist_* calls in tests pollute soc_inspect.db with
# synthetic test entities (e.g. "e1") that then appear in the demo.
_tmp = tempfile.NamedTemporaryFile(prefix="soc_inspect_test_", suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp.name}"
