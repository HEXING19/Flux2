from __future__ import annotations

import unittest
from typing import Any

from app.core.requester import APIRequester
from app.core.signature import Signature


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
    def test_signature_payload_transform_should_support_chinese_payload(self):
        signature = Signature(ak="demo-ak", sk="demo-sk")
        payload = '{"reason":"由安全早报一键处置触发","devices":[{"devName":"物联网安全网关"}]}'

        hashed = signature._payload_transform(payload)

        self.assertIsInstance(hashed, str)
        self.assertEqual(len(hashed), 64)

    def test_post_json_should_escape_non_ascii_for_signed_requests(self):
        requester = APIRequester(
            base_url="https://example.local",
            auth_code=None,
            access_key="demo-ak",
            secret_key="demo-sk",
            verify_ssl=False,
        )
        fake_session = FakeSession([FakeResponse(200, {"code": "Success", "data": {}})])
        requester.session = fake_session

        result = requester.request("POST", "/api/xdr/v1/responses/blockiprule/network", json_body={"reason": "物联网安全网关"})

        self.assertEqual(result.get("code"), "Success")
        self.assertEqual(len(fake_session.prepared_requests), 1)
        body = fake_session.prepared_requests[0].body.decode("utf-8") if isinstance(fake_session.prepared_requests[0].body, bytes) else fake_session.prepared_requests[0].body
        self.assertIn("\\u7269\\u8054\\u7f51\\u5b89\\u5168\\u7f51\\u5173", body)
        self.assertNotIn("物联网安全网关", body)

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
