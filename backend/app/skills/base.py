from __future__ import annotations

from abc import ABC, abstractmethod
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
        import ipaddress
        from sqlmodel import select
        from app.core.db import session_scope
        from app.models.db_models import SafetyGateRule

        # 知名公共 DNS 或基础服务 IP
        well_known_ips = {
            "8.8.8.8", "8.8.4.4",      # Google DNS
            "1.1.1.1", "1.0.0.1",      # Cloudflare DNS
            "114.114.114.114",         # 114 DNS
            "223.5.5.5", "223.6.6.6",  # Ali DNS
            "119.29.29.29",            # Tencent DNS
            "127.0.0.1", "0.0.0.0"     # Loopback/Unspecified
        }

        # 知名公共基础域名
        well_known_domains = {
            "localhost", "github.com", "google.com", "baidu.com", "qq.com"
        }

        # 保留的内网或高危网段
        reserved_networks = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
        ]

        # 动态加载用户自定义前端拦截名单
        custom_targets = set()
        try:
            with session_scope() as session:
                custom_rules = session.exec(select(SafetyGateRule)).all()
                for rule in custom_rules:
                    custom_targets.add(rule.target.strip().lower())
        except Exception:
            # In early init or isolated unit tests the table may not exist yet.
            custom_targets = set()

        def _is_dangerous(val: str) -> bool:
            val = val.strip().lower()
            if val in well_known_ips or val in well_known_domains or val in custom_targets:
                return True
            try:
                ip_obj = ipaddress.ip_address(val)
                for net in reserved_networks:
                    if ip_obj in net:
                        return True
            except ValueError:
                pass  # Not an IP address, ignore CIDR check
            return False

        dump = model.model_dump()
        for key, value in dump.items():
            if isinstance(value, str):
                if _is_dangerous(value):
                    raise ValidationGuardException(f"Safety Gate 拦截: 禁止对系统保留/高危/自定义白名单目标 ({value}) 执行该操作。")
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and _is_dangerous(item):
                        raise ValidationGuardException(f"Safety Gate 拦截: 禁止对系统保留/高危/自定义白名单目标 ({item}) 执行该操作。")


    @abstractmethod
    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        raise NotImplementedError
