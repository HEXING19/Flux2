from __future__ import annotations

from abc import ABC, abstractmethod
import ipaddress
from typing import Any

from pydantic import BaseModel, ValidationError

from app.core.context import SkillContextManager
from app.core.exceptions import MissingParameterException, ValidationGuardException
from app.core.requester import APIRequester
from app.core.time_parser import parse_time_range


class SkillInput(BaseModel):
    pass


class BaseSkill(ABC):
    name: str = "base"
    __init_schema__ = SkillInput
    required_fields: list[str] = []
    requires_confirmation: bool = False
    apply_safety_gate: bool = False

    def __init__(self, requester: APIRequester, context_manager: SkillContextManager):
        self.requester = requester
        self.context_manager = context_manager

    def validate_and_prepare(self, session_id: str, params: dict[str, Any]) -> BaseModel:
        merged = self.context_manager.inherit_params(session_id, params, self.required_fields)
        missing = [f for f in self.required_fields if merged.get(f) in (None, "", [], {})]
        if missing:
            fields = "、".join(missing)
            raise MissingParameterException(
                skill_name=self.name,
                missing_fields=missing,
                question=f"为了执行 {self.name}，还缺少参数：{fields}。请补充后我继续执行。",
            )

        if merged.get("time_text") and not (merged.get("startTimestamp") and merged.get("endTimestamp")):
            start_ts, end_ts = parse_time_range(merged["time_text"])
            merged["startTimestamp"] = start_ts
            merged["endTimestamp"] = end_ts

        try:
            model = self.__init_schema__(**merged)
        except ValidationError as exc:
            raise ValidationGuardException(f"{self.name} 参数校验失败 (Flux IR Validation Failed): {exc}") from exc

        if self.apply_safety_gate:
            self.run_safety_gate(model)

        self.context_manager.update_params(session_id, model.model_dump(exclude_none=True))
        return model

    def run_safety_gate(self, model: BaseModel) -> None:
        """
        Global Safety Gate (安全防卫门)
        在 IR (Schema) 校验通过后、执行实际操作前拦截高危指令。可被子类继承以实现特定业务的安全红线。
        """
        from sqlmodel import select
        from app.core.db import session_scope
        from app.models.db_models import SafetyGateRule

        protected_ips = {
            "8.8.8.8", "8.8.4.4",      # Google DNS
            "1.1.1.1", "1.0.0.1",      # Cloudflare DNS
            "114.114.114.114",         # 114 DNS
            "223.5.5.5", "223.6.6.6",  # Ali DNS
            "119.29.29.29",            # Tencent DNS
            "127.0.0.1", "0.0.0.0"     # Loopback/Unspecified
        }

        protected_domains = {
            "localhost", "github.com", "google.com", "baidu.com", "qq.com"
        }

        protected_networks = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
        ]

        custom_ips: set[str] = set()
        custom_domains: set[str] = set()
        try:
            with session_scope() as session:
                custom_rules = session.exec(select(SafetyGateRule)).all()
                for rule in custom_rules:
                    target = str(rule.target or "").strip().lower()
                    rule_type = str(rule.rule_type or "").strip().lower()
                    if not target:
                        continue
                    if rule_type == "cidr":
                        try:
                            net = ipaddress.ip_network(target, strict=False)
                        except ValueError:
                            continue
                        if isinstance(net, ipaddress.IPv4Network):
                            protected_networks.append(net)
                        continue
                    if rule_type == "domain":
                        custom_domains.add(target)
                        continue
                    custom_ips.add(target)
        except Exception:
            # In early init or isolated unit tests the table may not exist yet.
            custom_ips = set()
            custom_domains = set()

        def _is_dangerous(val: str) -> bool:
            normalized = val.strip().lower()
            if normalized in protected_ips or normalized in protected_domains or normalized in custom_ips or normalized in custom_domains:
                return True
            try:
                ip_obj = ipaddress.ip_address(normalized)
                for net in protected_networks:
                    if ip_obj in net:
                        return True
            except ValueError:
                pass
            return False

        dump = model.model_dump()
        self.ensure_safe_gate_targets(dump, checker=_is_dangerous)

    def ensure_safe_gate_targets(
        self,
        payload: dict[str, Any],
        *,
        checker: Any | None = None,
    ) -> None:
        if checker is None:
            checker = self._build_safety_target_checker()

        for value in payload.values():
            if isinstance(value, str):
                if checker(value):
                    raise ValidationGuardException(f"Safety Gate 拦截: 禁止对系统保留/高危/自定义白名单目标 ({value}) 执行该操作。")
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and checker(item):
                        raise ValidationGuardException(f"Safety Gate 拦截: 禁止对系统保留/高危/自定义白名单目标 ({item}) 执行该操作。")

    def _build_safety_target_checker(self):
        import ipaddress
        from sqlmodel import select
        from app.core.db import session_scope
        from app.models.db_models import SafetyGateRule

        protected_ips = {
            "8.8.8.8", "8.8.4.4",
            "1.1.1.1", "1.0.0.1",
            "114.114.114.114",
            "223.5.5.5", "223.6.6.6",
            "119.29.29.29",
            "127.0.0.1", "0.0.0.0",
        }
        protected_domains = {"localhost", "github.com", "google.com", "baidu.com", "qq.com"}
        protected_networks = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
        ]
        custom_ips: set[str] = set()
        custom_domains: set[str] = set()
        try:
            with session_scope() as session:
                custom_rules = session.exec(select(SafetyGateRule)).all()
                for rule in custom_rules:
                    target = str(rule.target or "").strip().lower()
                    rule_type = str(rule.rule_type or "").strip().lower()
                    if not target:
                        continue
                    if rule_type == "cidr":
                        try:
                            net = ipaddress.ip_network(target, strict=False)
                        except ValueError:
                            continue
                        if isinstance(net, ipaddress.IPv4Network):
                            protected_networks.append(net)
                        continue
                    if rule_type == "domain":
                        custom_domains.add(target)
                        continue
                    custom_ips.add(target)
        except Exception:
            custom_ips = set()
            custom_domains = set()

        def _is_dangerous(val: str) -> bool:
            normalized = val.strip().lower()
            if normalized in protected_ips or normalized in protected_domains or normalized in custom_ips or normalized in custom_domains:
                return True
            try:
                ip_obj = ipaddress.ip_address(normalized)
                for net in protected_networks:
                    if ip_obj in net:
                        return True
            except ValueError:
                pass
            return False

        return _is_dangerous


    @abstractmethod
    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        raise NotImplementedError
