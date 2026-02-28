from __future__ import annotations

import unittest
from typing import Any

from app.core.requester import APIRequester


class FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, Any] | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class FakeSession:
    def __init__(self, responses: list[FakeResponse]):
        self._responses = list(responses)
        self.verify = False
        self.prepared_requests = []

    def send(self, prepared, timeout=15):
        _ = timeout
        self.prepared_requests.append(prepared)
        if not self._responses:
            raise RuntimeError("no fake response configured")
        return self._responses.pop(0)


class RequesterTest(unittest.TestCase):
    def test_get_request_should_not_send_empty_json_body(self):
        requester = APIRequester(
            base_url="https://example.local",
            auth_code=None,
            access_key=None,
            secret_key=None,
            verify_ssl=False,
        )
        fake_session = FakeSession([FakeResponse(200, {"code": "Success", "data": {}})])
        requester.session = fake_session

        result = requester.request("GET", "/api/xdr/v1/incidents/demo/entities/ip")

        self.assertEqual(result.get("code"), "Success")
        self.assertEqual(len(fake_session.prepared_requests), 1)
        self.assertIsNone(fake_session.prepared_requests[0].body)

    def test_http_401_should_return_actionable_auth_message(self):
        requester = APIRequester(
            base_url="https://example.local",
            auth_code=None,
            access_key=None,
            secret_key=None,
            verify_ssl=False,
        )
        fake_session = FakeSession([FakeResponse(401, {"message": "Unauthorized"})])
        requester.session = fake_session

        result = requester.request("GET", "/api/xdr/v1/incidents/demo/entities/ip")

        self.assertEqual(result.get("code"), "Failed")
        self.assertIn("认证失败或权限不足", result.get("message", ""))
        self.assertIn("request_id=", result.get("message", ""))


if __name__ == "__main__":
    unittest.main()

