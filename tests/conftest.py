"""Shared fixtures. Fake data only: example_user, example.com, 192.0.2.0/24, +1 555."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

# Keep test windows off screen and keep any accidental data out of the real cases folder.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("NIGHTGLASS_DATA_DIR", str(tmp_path / "data"))


@pytest.fixture(autouse=True)
def _no_real_credentials(monkeypatch):
    """Tests never read or write the real Windows Credential Manager."""
    import keyring

    from core.secrets import MemoryKeyring

    memory = MemoryKeyring()
    monkeypatch.setattr(keyring, "get_keyring", lambda: memory)


class FakeClock:
    def __init__(self, start: datetime):
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs) -> None:
        self.now += timedelta(**kwargs)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(datetime(2026, 10, 29, 19, 58, tzinfo=timezone.utc))


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "data" / "nightglass.db"


@pytest.fixture
def db(db_path):
    from core.db import Database

    database = Database(db_path)
    yield database
    database.close()


@pytest.fixture
def manager(db, clock):
    from core.cases import CaseManager

    return CaseManager(db, now=clock)


@pytest.fixture
def new_case():
    from core.cases import LookupMode, NewCase

    def make(**overrides) -> NewCase:
        fields = dict(
            name="Account impersonation review",
            purpose="Check whether public profiles impersonate my own brand account.",
            authorized_scope='My own accounts and example.com. Public profiles using "example_user".',
            allowed_modes=(LookupMode.LOCAL, LookupMode.EXTERNAL_PASSIVE),
            first_target_type="username",
            first_target_value="example_user",
        )
        fields.update(overrides)
        return NewCase(**fields)

    return make


@pytest.fixture(scope="session")
def themed_app(qapp):
    from app import theme

    theme.apply_theme(qapp)
    return qapp
