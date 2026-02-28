from __future__ import annotations

import unittest

from sqlmodel import Session, delete

from app.core.context import SkillContextManager
from app.core.db import engine, init_db
from app.models.db_models import SessionState


class ContextPersistenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        self.session_id = "persist-test-session"
        with Session(engine) as session:
            session.exec(delete(SessionState).where(SessionState.session_id == self.session_id))
            session.commit()

    def test_context_state_is_recoverable(self):
        manager1 = SkillContextManager(enable_persistence=True)
        manager1.update_params(self.session_id, {"last_event_uuid": "incident-001"})
        manager1.store_index_mapping(self.session_id, "events", ["incident-001", "incident-002"])
        manager1.save_pending_action(self.session_id, {"intent": "event_action", "params": {"deal_status": 40}})
        manager1.save_pending_form(self.session_id, {"token": "t1", "intent": "block_action", "params": {"views": ["1.1.1.1"]}})

        manager2 = SkillContextManager(enable_persistence=True)
        self.assertEqual(manager2.get_param(self.session_id, "last_event_uuid"), "incident-001")
        self.assertEqual(manager2.get_index_mapping(self.session_id, "events"), ["incident-001", "incident-002"])
        self.assertIsNotNone(manager2.peek_pending_action(self.session_id))
        self.assertIsNotNone(manager2.peek_pending_form(self.session_id))

        manager2.pop_pending_action(self.session_id)
        manager2.pop_pending_form(self.session_id)
        manager3 = SkillContextManager(enable_persistence=True)
        self.assertIsNone(manager3.peek_pending_action(self.session_id))
        self.assertIsNone(manager3.peek_pending_form(self.session_id))


if __name__ == "__main__":
    unittest.main()

