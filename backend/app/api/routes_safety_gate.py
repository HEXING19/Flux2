from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator, model_validator
from sqlmodel import Session, select

from app.core.db import get_session
from app.core.validation import clean_optional_text, clean_text, validate_cidr, validate_domain, validate_ipv4
from app.models.db_models import SafetyGateRule

router = APIRouter(prefix="/api/config/safety_gate", tags=["safety_gate"])


class SafetyRuleCreate(BaseModel):
    rule_type: str
    target: str
    description: str | None = None

    @field_validator("rule_type")
    @classmethod
    def validate_rule_type(cls, value: str) -> str:
        normalized = clean_text(value).lower()
        if normalized not in {"ip", "domain", "cidr"}:
            raise ValueError("rule_type 仅支持 ip、domain、cidr。")
        return normalized

    @field_validator("description", mode="before")
    @classmethod
    def normalize_description(cls, value: str | None) -> str | None:
        return clean_optional_text(value)

    @model_validator(mode="after")
    def validate_target(self) -> "SafetyRuleCreate":
        if self.rule_type == "ip":
            self.target = validate_ipv4(self.target, field_name="target")
        elif self.rule_type == "domain":
            self.target = validate_domain(self.target, field_name="target")
        else:
            self.target = validate_cidr(self.target, field_name="target")
        return self


@router.get("/")
def list_rules(session: Session = Depends(get_session)):
    rules = session.exec(select(SafetyGateRule).order_by(SafetyGateRule.created_at.desc())).all()
    user_rules = [
        {
            "id": r.id,
            "rule_type": r.rule_type,
            "target": r.target,
            "description": r.description,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "is_builtin": False
        }
        for r in rules
    ]

    builtin_rules = []
    builtin_ips = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "114.114.114.114", "223.5.5.5", "223.6.6.6", "119.29.29.29", "127.0.0.1", "0.0.0.0"]
    for ip in builtin_ips:
        builtin_rules.append({"id": f"builtin_ip_{ip}", "rule_type": "ip", "target": ip, "description": "系统内置: 知名公共 DNS 或基础服务", "is_builtin": True})

    builtin_domains = ["localhost", "github.com", "google.com", "baidu.com", "qq.com"]
    for domain in builtin_domains:
        builtin_rules.append({"id": f"builtin_domain_{domain}", "rule_type": "domain", "target": domain, "description": "系统内置: 知名公共基础域名", "is_builtin": True})

    builtin_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
    for cidr in builtin_cidrs:
        builtin_rules.append({"id": f"builtin_cidr_{cidr.replace('/', '_')}", "rule_type": "cidr", "target": cidr, "description": "系统内置: 保留的内网或高危网段", "is_builtin": True})

    return builtin_rules + user_rules


@router.post("/")
def create_rule(payload: SafetyRuleCreate, session: Session = Depends(get_session)):
    # Check if target already exists mapped by another rule to prevent confusing overlap/dupes (simplification)
    existing = session.exec(select(SafetyGateRule).where(SafetyGateRule.target == payload.target)).first()
    if existing:
        raise HTTPException(status_code=400, detail="该目标已经被添加到安全防线中")

    rule = SafetyGateRule(rule_type=payload.rule_type, target=payload.target, description=payload.description)
    session.add(rule)
    session.commit()
    session.refresh(rule)
    return {
        "id": rule.id,
        "rule_type": rule.rule_type,
        "target": rule.target,
        "description": rule.description,
    }

@router.delete("/{rule_id}")
def delete_rule(rule_id: int, session: Session = Depends(get_session)):
    rule = session.get(SafetyGateRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="规则不存在")
    session.delete(rule)
    session.commit()
    return {"success": True}
