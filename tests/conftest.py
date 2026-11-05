"""Shared pytest fixtures."""
from pathlib import Path

import pytest

from siem.ingestion.queue_manager import LogQueue


@pytest.fixture
def log_queue():
    return LogQueue(max_size=1000)


@pytest.fixture
def session_factory(tmp_path):
    """A session factory bound to a migrated, temporary SQLite database."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from siem.storage.migrations import run_migrations

    db_path = tmp_path / "test.db"
    run_migrations(db_path)
    engine = create_engine(f"sqlite:///{db_path}", future=True)
    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    yield factory
    engine.dispose()


@pytest.fixture
def storage(session_factory):
    from siem.storage.service import StorageService

    return StorageService(session_factory=session_factory)


@pytest.fixture
def fk_session_factory(tmp_path):
    """Session factory whose SQLite connection enforces foreign keys."""
    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import sessionmaker

    from siem.storage.migrations import run_migrations

    db_path = tmp_path / "test_fk.db"
    run_migrations(db_path)
    engine = create_engine(f"sqlite:///{db_path}", future=True)

    @event.listens_for(engine, "connect")
    def _enable_fk(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    yield factory
    engine.dispose()


# -- web fixtures ----------------------------------------------------------

def make_web_config(project_root: Path, csrf: bool = False):
    from siem.core.config import Config

    return Config(
        {
            "system": {"name": "SIEM Log Correlator", "version": "1.0.0"},
            "web": {
                "host": "127.0.0.1",
                "port": 5000,
                "secret_key": "test-secret-key",
                "session_timeout_minutes": 30,
                "debug": False,
                "csrf_enabled": csrf,
                "socketio_cors": "*",
            },
        },
        project_root=project_root,
    )


@pytest.fixture
def web_config(tmp_path):
    return make_web_config(tmp_path, csrf=False)


@pytest.fixture
def web_app(web_config, session_factory):
    from siem.storage.service import StorageService
    from siem.web.app import create_app

    storage = StorageService(session_factory=session_factory, config=web_config)
    app = create_app(web_config, storage=storage)
    app.config.update(TESTING=True)
    return app


@pytest.fixture
def client(web_app):
    return web_app.test_client()


@pytest.fixture
def admin_user(web_app):
    """Create an admin account and return its credentials."""
    storage = web_app.extensions["siem_storage"]
    storage.users.create("admin", "admin-pass", role="admin")
    return {"username": "admin", "password": "admin-pass"}


@pytest.fixture
def auth_client(client, admin_user):
    """A test client already logged in as admin."""
    resp = client.post("/login", data=admin_user, follow_redirects=False)
    assert resp.status_code in (302, 303)
    return client


@pytest.fixture
def web_app_csrf(tmp_path, session_factory):
    from siem.storage.service import StorageService
    from siem.web.app import create_app

    config = make_web_config(tmp_path, csrf=True)
    storage = StorageService(session_factory=session_factory, config=config)
    app = create_app(config, storage=storage)
    app.config.update(TESTING=True)
    return app


@pytest.fixture
def csrf_client(web_app_csrf):
    return web_app_csrf.test_client()
