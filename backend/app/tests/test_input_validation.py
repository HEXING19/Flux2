from __future__ import annotations

import unittest

from pydantic import ValidationError
from sqlmodel import Session

from app.api.routes_safety_gate import SafetyRuleCreate
from app.core.db import engine, init_db
from app.models.schemas import LoginRequest, WorkflowConfigIn
from app.workflow.service import workflow_service


class InputValidationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_login_request_should_reject_invalid_base_url(self):
        with self.assertRaises(ValidationError):
            LoginRequest(base_url="not-a-url", auth_code="demo-auth-code")

    def test_workflow_schema_should_reject_invalid_cron_and_webhook(self):
        with self.assertRaises(ValidationError):
            WorkflowConfigIn(
                name="bad workflow",
                cron_expr="0 9 * *",
                levels=[3, 4],
                webhook_url="not-a-url",
            )

    def test_workflow_service_should_reject_invalid_levels(self):
        with Session(engine) as session:
            with self.assertRaises(ValueError):
                workflow_service.create_or_update_workflow(
                    session,
                    {
                        "name": "bad workflow",
                        "cron_expr": "0 9 * * *",
                        "levels": [9],
                        "require_approval": True,
                    },
                )

    def test_safety_rule_should_validate_target_by_type(self):
        with self.assertRaises(ValidationError):
            SafetyRuleCreate(rule_type="ip", target="bad-ip")
        with self.assertRaises(ValidationError):
            SafetyRuleCreate(rule_type="cidr", target="10.10.10.10")


if __name__ == "__main__":
    unittest.main()
