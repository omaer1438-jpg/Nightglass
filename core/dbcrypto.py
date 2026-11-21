"""Encrypted case database (alternative to SQLCipher, plan section 11).

The database lives on disk only as `nightglass.db.enc`:

    MAGIC (6) | salt (16) | nonce (12) | AES-256-GCM ciphertext + tag

The key comes from the master password via scrypt and is kept in memory for the
session. While Nightglass runs, SQLite works on an in-memory copy; after every
write the whole database is re-encrypted with a fresh nonce and written
atomically. No plaintext copy of the database is ever written to disk.
A forgotten password cannot be recovered.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"NGDB1\x00"
SALT_BYTES, NONCE_BYTES = 16, 12
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
MIN_PASSWORD_LENGTH = 10


class WrongPassword(Exception):
    pass


class NotEncryptedFile(Exception):
    pass


def check_password_strength(password: str) -> str | None:
    """Problem with the new password, or None if it's acceptable."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Use at least {MIN_PASSWORD_LENGTH} characters."
    if password.strip() != password:
        return "Remove spaces at the start or end."
    if len(set(password)) < 5:
        return "Use a less repetitive password."
    return None


def derive_key(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(password.encode("utf-8"))


class DbCrypto:
    """Holds the session key for one encrypted database file."""

    def __init__(self, path: Path, key: bytes, salt: bytes):
        self.path = Path(path)
        self._key = key
        self._salt = salt

    # ---- opening

    @classmethod
    def create(cls, path: Path, password: str) -> DbCrypto:
        salt = secrets.token_bytes(SALT_BYTES)
        return cls(path, derive_key(password, salt), salt)

    @classmethod
    def unlock(cls, path: Path, password: str) -> tuple[DbCrypto, bytes]:
        """(crypto, decrypted database bytes). Raises WrongPassword."""
        blob = Path(path).read_bytes()
        if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + SALT_BYTES + NONCE_BYTES + 16:
            raise NotEncryptedFile(f"{path} is not a Nightglass encrypted database.")
        offset = len(MAGIC)
        salt = blob[offset:offset + SALT_BYTES]
        nonce = blob[offset + SALT_BYTES:offset + SALT_BYTES + NONCE_BYTES]
        ciphertext = blob[offset + SALT_BYTES + NONCE_BYTES:]
        key = derive_key(password, salt)
        try:
            data = AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
        except InvalidTag as exc:
            raise WrongPassword("That password doesn't open this database.") from exc
        return cls(path, key, salt), data

    # ---- saving

    def save(self, data: bytes) -> None:
        nonce = secrets.token_bytes(NONCE_BYTES)
        blob = MAGIC + self._salt + nonce + AESGCM(self._key).encrypt(nonce, data, MAGIC)
        tmp = self.path.with_name(self.path.name + ".tmp")
        with open(tmp, "wb") as handle:
            handle.write(blob)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.path)

    def rekey(self, new_password: str) -> None:
        """Change the password; the next save() uses the new key."""
        self._salt = secrets.token_bytes(SALT_BYTES)
        self._key = derive_key(new_password, self._salt)


def wipe_file(path: Path) -> None:
    """Overwrite then delete (best effort: SSDs and backups may still hold old blocks)."""
    path = Path(path)
    if not path.exists():
        return
    try:
        size = path.stat().st_size
        with open(path, "r+b") as handle:
            remaining = size
            while remaining > 0:
                chunk = min(remaining, 1 << 20)
                handle.write(b"\x00" * chunk)
                remaining -= chunk
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        pass
    path.unlink(missing_ok=True)


def plain_files(db_path: Path) -> list[Path]:
    return [Path(db_path), Path(f"{db_path}-wal"), Path(f"{db_path}-shm"), Path(f"{db_path}-journal")]
