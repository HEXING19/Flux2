from __future__ import annotations
from datetime import datetime, timezone

from sqlmodel import Session, delete, select

from app.core.semantic_rules import (
    decode_rule_payload,
    encode_rule_payload,
    normalize_rule_text,
    normalize_rule_value,
    validate_action_type,
    validate_description,
    validate_match_mode,
    validate_phrase,
    validate_rule_domain,
    validate_rule_slot,
)
from app.models.db_models import CoreAsset, ProviderConfig, SemanticRule, ThreatIntelConfig, XDRCredential


class ConfigService:
    def __init__(self, session: Session):
        self.session = session

    def upsert_provider(self, payload: dict) -> ProviderConfig:
        provider = payload["provider"]
        existing = self.session.exec(select(ProviderConfig).where(ProviderConfig.provider == provider)).first()
        if existing:
            for key, value in payload.items():
                setattr(existing, key, value)
            existing.updated_at = datetime.now(timezone.utc)
            self.session.add(existing)
            self.session.commit()
            self.session.refresh(existing)
            return existing

        model = ProviderConfig(**payload)
        self.session.add(model)
        self.session.commit()
        self.session.refresh(model)
        return model

    def list_providers(self) -> list[ProviderConfig]:
        rows = self.session.exec(select(ProviderConfig).order_by(ProviderConfig.provider)).all()
        return [row for row in rows if row.provider != "mock"]

    def save_xdr_credential(self, payload: dict) -> XDRCredential:
        existing = self.session.exec(select(XDRCredential).order_by(XDRCredential.id.desc())).first()
        if existing:
            for key, value in payload.items():
                setattr(existing, key, value)
            existing.updated_at = datetime.now(timezone.utc)
            self.session.add(existing)
            self.session.commit()
            self.session.refresh(existing)
            return existing

        credential = XDRCredential(**payload)
        self.session.add(credential)
        self.session.commit()
        self.session.refresh(credential)
        return credential

    def get_latest_credential(self) -> XDRCredential | None:
        return self.session.exec(select(XDRCredential).order_by(XDRCredential.id.desc())).first()

    def clear_xdr_credentials(self) -> None:
        self.session.exec(delete(XDRCredential))
        self.session.commit()

    def get_threatbook_config(self) -> ThreatIntelConfig | None:
        return self.session.exec(
            select(ThreatIntelConfig).where(ThreatIntelConfig.provider == "threatbook")
        ).first()

    def upsert_threatbook_config(self, *, api_key: str | None, enabled: bool) -> ThreatIntelConfig:
        existing = self.get_threatbook_config()
        normalized_key = api_key.strip() if api_key is not None else None
        if existing:
            if normalized_key is not None:
                existing.api_key = normalized_key or None
            existing.enabled = enabled
            existing.updated_at = datetime.now(timezone.utc)
            self.session.add(existing)
            self.session.commit()
            self.session.refresh(existing)
            return existing

        model = ThreatIntelConfig(
            provider="threatbook",
            api_key=normalized_key or None,
            enabled=enabled,
            updated_at=datetime.now(timezone.utc),
        )
        self.session.add(model)
        self.session.commit()
        self.session.refresh(model)
        return model

    def list_semantic_rules(self, *, enabled_only: bool = False) -> list[SemanticRule]:
        query = select(SemanticRule)
        if enabled_only:
            query = query.where(SemanticRule.enabled == True)  # noqa: E712
        query = query.order_by(SemanticRule.priority.asc(), SemanticRule.updated_at.desc(), SemanticRule.id.desc())
        return list(self.session.exec(query).all())

    @staticmethod
    def decode_semantic_rule_payload(rule: SemanticRule) -> dict[str, object]:
        return decode_rule_payload(rule.mapped_value_json)

    def upsert_semantic_rule(self, payload: dict, *, rule_id: int | None = None) -> SemanticRule:
        domain = validate_rule_domain(payload.get("domain"))
        slot_name = validate_rule_slot(domain, payload.get("slot_name"))
        match_mode = validate_match_mode(payload.get("match_mode") or "contains")
        phrase = validate_phrase(payload.get("phrase"), match_mode=match_mode)
        phrase_key = normalize_rule_text(phrase)
        action_type = validate_action_type(domain, slot_name, payload.get("action_type") or None)
        rule_value = normalize_rule_value(domain, slot_name, action_type, payload.get("rule_value"))
        description = validate_description(payload.get("description"))
        enabled = bool(payload.get("enabled", True))
        priority = int(payload.get("priority", 100))
        if priority < 0:
            raise ValueError("priority 不能小于 0。")

        siblings = self.session.exec(
            select(SemanticRule).where(SemanticRule.domain == domain, SemanticRule.slot_name == slot_name)
        ).all()
        for row in siblings:
            if row.phrase_key == phrase_key and row.id != rule_id:
                raise ValueError("同一作用域和槽位下已存在相同话术。")

        if rule_id is not None:
            model = self.session.get(SemanticRule, rule_id)
            if not model:
                raise ValueError("语义规则不存在。")
        else:
            model = SemanticRule(
                domain=domain,
                slot_name=slot_name,
                phrase=phrase,
                phrase_key=phrase_key,
                match_mode=match_mode,
                mapped_value_json="[]",
                enabled=enabled,
                priority=priority,
                description=description,
            )

        model.domain = domain
        model.slot_name = slot_name
        model.phrase = phrase
        model.phrase_key = phrase_key
        model.match_mode = match_mode
        model.mapped_value_json = encode_rule_payload(action_type, rule_value)
        model.description = description
        model.enabled = enabled
        model.priority = priority
        model.updated_at = datetime.now(timezone.utc)

        self.session.add(model)
        self.session.commit()
        self.session.refresh(model)
        return model

    def delete_semantic_rule(self, rule_id: int) -> bool:
        row = self.session.get(SemanticRule, rule_id)
        if not row:
            return False
        self.session.delete(row)
        self.session.commit()
        return True

    def list_core_assets(self) -> list[CoreAsset]:
        return list(self.session.exec(select(CoreAsset).order_by(CoreAsset.updated_at.desc())).all())

    def create_core_asset(self, payload: dict) -> CoreAsset:
        existing = self.session.exec(select(CoreAsset).where(CoreAsset.asset_ip == payload["asset_ip"])).first()
        if existing:
            for key, value in payload.items():
                setattr(existing, key, value)
            existing.updated_at = datetime.now(timezone.utc)
            self.session.add(existing)
            self.session.commit()
            self.session.refresh(existing)
            return existing

        asset = CoreAsset(**payload, updated_at=datetime.now(timezone.utc))
        self.session.add(asset)
        self.session.commit()
        self.session.refresh(asset)
        return asset

    def delete_core_asset(self, asset_id: int) -> bool:
        row = self.session.get(CoreAsset, asset_id)
        if not row:
            return False
        self.session.delete(row)
        self.session.commit()
        return True
