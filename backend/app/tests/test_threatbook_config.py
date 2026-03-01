from __future__ import annotations

import unittest

from sqlmodel import Session, delete

from app.core.db import engine, init_db
from app.core.settings import settings
from app.core.threatbook import resolve_threatbook_api_key
from app.models.db_models import ThreatIntelConfig


class ThreatbookConfigTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        self._old_env_key = settings.threatbook_api_key
        with Session(engine) as session:
            session.exec(delete(ThreatIntelConfig))
            session.commit()

    def tearDown(self):
        settings.threatbook_api_key = self._old_env_key

    def test_db_key_should_override_env(self):
        settings.threatbook_api_key = "env-key-001"
        with Session(engine) as session:
            session.add(ThreatIntelConfig(provider="threatbook", api_key="db-key-001", enabled=True))
            session.commit()
        self.assertEqual(resolve_threatbook_api_key(), "db-key-001")

    def test_disabled_db_config_should_block_env_fallback(self):
        settings.threatbook_api_key = "env-key-001"
        with Session(engine) as session:
            session.add(ThreatIntelConfig(provider="threatbook", api_key="db-key-001", enabled=False))
            session.commit()
        self.assertIsNone(resolve_threatbook_api_key())


if __name__ == "__main__":
    unittest.main()
