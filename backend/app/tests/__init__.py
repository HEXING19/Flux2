from __future__ import annotations

import os
from pathlib import Path


_TEST_DB_PATH = Path(__file__).resolve().parents[3] / "data" / "test_flux.db"
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DB_PATH", str(_TEST_DB_PATH))
