from __future__ import annotations

import unittest
from unittest.mock import patch

from sqlmodel import Session, delete

from app.api.routes_auth import auth_status, login, logout
from app.core.db import engine, init_db
from app.models.db_models import XDRCredential
from app.models.schemas import LoginRequest


class FakeRequester:
    def request(self, method, path, *, json_body=None, timeout=15, max_retries=1):
        _ = (method, path, json_body, timeout, max_retries)
        return {"code": "Success"}


class AuthRoutesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        with Session(engine) as session:
            session.exec(delete(XDRCredential))
            session.commit()

    def test_login_status_and_logout_should_manage_persisted_credential(self):
        payload = LoginRequest(
            base_url="https://xdr.example.local",
            access_key="demo-ak",
            secret_key="demo-sk",
            verify_ssl=False,
        )

        with Session(engine) as session:
            with patch("app.api.routes_auth._probe_connectivity", return_value={"code": "Success"}):
                result = login(payload, session)

            self.assertTrue(result.success)

        with Session(engine) as session:
            with patch("app.core.requester.get_requester_from_credential", return_value=FakeRequester()):
                status = auth_status(session)

            self.assertTrue(status["authenticated"])
            self.assertEqual(status["base_url"], "https://xdr.example.local")
            self.assertTrue(status["connected"])

        with Session(engine) as session:
            result = logout(session)
            self.assertTrue(result.success)

        with Session(engine) as session:
            status = auth_status(session)
            self.assertFalse(status["authenticated"])


if __name__ == "__main__":
    unittest.main()
