from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlmodel import Session, SQLModel, create_engine

from .settings import settings


engine = create_engine(
    settings.sqlite_url,
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
)


def init_db() -> None:
    SQLModel.metadata.create_all(engine)


@contextmanager
def session_scope() -> Iterator[Session]:
    session = Session(engine)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
