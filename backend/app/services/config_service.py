from __future__ import annotations

from datetime import datetime

from sqlmodel import Session, select

from app.models.db_models import ProviderConfig, XDRCredential


class ConfigService:
    def __init__(self, session: Session):
        self.session = session

    def upsert_provider(self, payload: dict) -> ProviderConfig:
        provider = payload["provider"]
        existing = self.session.exec(select(ProviderConfig).where(ProviderConfig.provider == provider)).first()
        if existing:
            for key, value in payload.items():
                setattr(existing, key, value)
            existing.updated_at = datetime.utcnow()
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
            existing.updated_at = datetime.utcnow()
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
