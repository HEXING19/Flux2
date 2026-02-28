from __future__ import annotations

import unittest
from unittest.mock import patch

from sqlmodel import Session

from app.core.db import engine, init_db
from app.services.chat_service import ChatService


class FakeRequester:
    def request(self, method, path, *, json_body=None, params=None, timeout=15):
        _ = (method, path, json_body, params, timeout)
        return {"code": "Success", "message": "OK", "data": {"item": []}}


class PipelineSafetyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_ambiguous_bulk_high_risk_is_blocked(self):
        with Session(engine) as session:
            with patch("app.services.chat_service.get_requester_from_credential", return_value=FakeRequester()):
                chat = ChatService(session)
                payloads = chat.handle("pipe-safety-1", "把全部都封禁")
                self.assertEqual(payloads[0]["type"], "text")
                self.assertIn("拦截", payloads[0]["data"].get("title", ""))


if __name__ == "__main__":
    unittest.main()

