from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from fastapi import Request
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from .models import Base


class Database:
    def __init__(self, url: str):
        options: dict[str, object] = {"future": True, "pool_pre_ping": True}
        self.sqlite_path: Path | None = None
        if url.startswith("sqlite"):
            options["connect_args"] = {"check_same_thread": False}
            if url in {"sqlite://", "sqlite:///:memory:"}:
                options["poolclass"] = StaticPool
            else:
                parsed = make_url(url)
                if parsed.database and parsed.database != ":memory:":
                    self.sqlite_path = Path(parsed.database).expanduser()
        self.engine = create_engine(url, **options)
        self.session_factory = sessionmaker(
            bind=self.engine,
            class_=Session,
            expire_on_commit=False,
            autoflush=False,
        )

    def harden_local_file_permissions(self) -> None:
        """Keep the local SQLite evidence/credential store private where supported."""
        if self.sqlite_path is not None and self.sqlite_path.exists():
            try:
                self.sqlite_path.chmod(0o600)
            except OSError:
                pass

    def create_all(self) -> None:
        """Create test/development schema directly; release startup uses Alembic."""
        Base.metadata.create_all(self.engine)
        self.harden_local_file_permissions()

    def dispose(self) -> None:
        self.engine.dispose()


def get_db(request: Request) -> Generator[Session, None, None]:
    with request.app.state.database.session_factory() as session:
        yield session
