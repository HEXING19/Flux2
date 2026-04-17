from __future__ import annotations

import unittest

from sqlmodel import Session, delete, select

from app.api.routes_chat import clear_chat_sessions
from app.core.context import context_manager
from app.core.db import engine, init_db
from app.models.db_models import SessionState
from app.models.schemas import ChatSessionClearRequest


class ChatSessionClearTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        self.session_ids = ["clear-test-1", "clear-test-2", "clear-test-keep", "clear-test-missing"]
        context_manager.clear_sessions(self.session_ids)
        with Session(engine) as session:
            session.exec(delete(SessionState).where(SessionState.session_id.in_(self.session_ids)))
            session.commit()

    def tearDown(self):
        context_manager.clear_sessions(self.session_ids)
        with Session(engine) as session:
            session.exec(delete(SessionState).where(SessionState.session_id.in_(self.session_ids)))
            session.commit()

    def test_clear_chat_sessions_deletes_selected_state_and_cache_only(self):
        context_manager.update_params("clear-test-1", {"last_event_uuid": "incident-001"})
        context_manager.update_params("clear-test-2", {"last_event_uuid": "incident-002"})
        context_manager.update_params("clear-test-keep", {"last_event_uuid": "incident-keep"})

        payload = ChatSessionClearRequest(session_ids=["clear-test-1", "clear-test-2", "clear-test-missing"])
        with Session(engine) as session:
            result = clear_chat_sessions(payload, session)

        self.assertTrue(result["success"])
        self.assertEqual(result["deleted_count"], 2)
        self.assertEqual(result["missing_session_ids"], ["clear-test-missing"])

        with Session(engine) as session:
            remaining = set(session.exec(select(SessionState.session_id)).all())

        self.assertNotIn("clear-test-1", remaining)
        self.assertNotIn("clear-test-2", remaining)
        self.assertIn("clear-test-keep", remaining)
        self.assertIsNone(context_manager.get_param("clear-test-1", "last_event_uuid"))
        self.assertEqual(context_manager.get_param("clear-test-keep", "last_event_uuid"), "incident-keep")


if __name__ == "__main__":
    unittest.main()
