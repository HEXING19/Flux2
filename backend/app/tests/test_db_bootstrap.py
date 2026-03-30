from __future__ import annotations

import importlib
import os
import tempfile
import unittest
from pathlib import Path


class DatabaseBootstrapTest(unittest.TestCase):
    def test_db_module_should_create_missing_parent_directory_for_sqlite_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "nested" / "storage" / "flux.db"
            original_db_path = os.environ.get("DB_PATH")
            original_settings = importlib.import_module("app.core.settings")
            original_db = importlib.import_module("app.core.db")

            self.assertFalse(db_path.parent.exists())
            os.environ["DB_PATH"] = str(db_path)
            settings_module = importlib.reload(original_settings)
            db_module = importlib.reload(original_db)
            try:
                self.assertTrue(db_path.parent.exists())
                db_module.init_db()
                self.assertTrue(db_path.exists())
            finally:
                if original_db_path is None:
                    os.environ.pop("DB_PATH", None)
                else:
                    os.environ["DB_PATH"] = original_db_path
                importlib.reload(settings_module)
                importlib.reload(db_module)


if __name__ == "__main__":
    unittest.main()
