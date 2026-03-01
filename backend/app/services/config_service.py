from __future__ import annotations

from datetime import datetime, timezone

from sqlmodel import Session, select

from app.models.db_models import CoreAsset, ProviderConfig, ThreatIntelConfig, XDRCredential


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
