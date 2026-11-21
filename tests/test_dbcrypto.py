"""Encrypted database: no plaintext on disk, wrong password refused, on/off conversion."""

from __future__ import annotations

import sqlite3

import pytest

from core.cases import CaseManager
from core.db import Database, decrypt_existing, encrypt_existing
from core.dbcrypto import DbCrypto, NotEncryptedFile, WrongPassword, check_password_strength

PASSWORD = "example-master-passphrase"


def open_encrypted(path, password=PASSWORD) -> Database:
    crypto, data = DbCrypto.unlock(path, password)
    return Database(path, crypto=crypto, data=data)


def test_new_encrypted_database_never_writes_plaintext(tmp_path, new_case):
    enc = tmp_path / "nightglass.db.enc"
    db = Database(enc, crypto=DbCrypto.create(enc, PASSWORD))
    case = CaseManager(db).create_case(new_case())
    CaseManager(db).save_case(case.id, notes="secret note about example_user")
    db.close()

    blob = enc.read_bytes()
    assert blob.startswith(b"NGDB1")
    for needle in (b"example_user", b"secret note", b"SQLite format 3", b"Account impersonation"):
        assert needle not in blob
    assert sorted(p.name for p in tmp_path.iterdir()) == ["nightglass.db.enc"]

    again = open_encrypted(enc)
    assert CaseManager(again).get_case(case.id).notes == "secret note about example_user"
    assert again.encrypted and again.cache_path is None
    again.close()


def test_every_write_is_saved_immediately(tmp_path):
    enc = tmp_path / "nightglass.db.enc"
    db = Database(enc, crypto=DbCrypto.create(enc, PASSWORD))
    db.set_setting("default_timeout_s", 60)
    # Simulate a crash: no close(), reopen from disk.
    assert open_encrypted(enc).get_setting("default_timeout_s") == 60


def test_wrong_password_and_tampering(tmp_path):
    enc = tmp_path / "nightglass.db.enc"
    Database(enc, crypto=DbCrypto.create(enc, PASSWORD)).close()
    with pytest.raises(WrongPassword):
        DbCrypto.unlock(enc, "not-the-password")
    blob = bytearray(enc.read_bytes())
    blob[-5] ^= 0xFF
    enc.write_bytes(bytes(blob))
    with pytest.raises(WrongPassword):  # GCM tag fails on any modification
        DbCrypto.unlock(enc, PASSWORD)
    plain = tmp_path / "plain.db"
    sqlite3.connect(plain).close()
    plain.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)
    with pytest.raises(NotEncryptedFile):
        DbCrypto.unlock(plain, PASSWORD)


def test_change_password(tmp_path):
    enc = tmp_path / "nightglass.db.enc"
    db = Database(enc, crypto=DbCrypto.create(enc, PASSWORD))
    db.change_password("another-long-passphrase")
    db.close()
    with pytest.raises(WrongPassword):
        DbCrypto.unlock(enc, PASSWORD)
    assert open_encrypted(enc, "another-long-passphrase").schema_version >= 2


def test_convert_plain_to_encrypted_and_back(tmp_path, new_case):
    plain = tmp_path / "nightglass.db"
    enc = tmp_path / "nightglass.db.enc"
    db = Database(plain)
    case = CaseManager(db).create_case(new_case())
    db.close()

    encrypt_existing(plain, enc, PASSWORD)
    assert not plain.exists() and not (tmp_path / "nightglass.db-wal").exists()
    encrypted = open_encrypted(enc)
    assert CaseManager(encrypted).get_case(case.id).name == "Account impersonation review"
    data = encrypted.serialize()
    encrypted.close()

    decrypt_existing(enc, plain, data)
    assert not enc.exists()
    with Database(plain) as back:
        assert CaseManager(back).get_case(case.id).name == "Account impersonation review"


@pytest.mark.parametrize("password, ok", [("short", False), ("aaaaaaaaaaaa", False), (" padded-pass ", False),
                                          ("correct horse battery", True)])
def test_password_strength(password, ok):
    assert (check_password_strength(password) is None) is ok
