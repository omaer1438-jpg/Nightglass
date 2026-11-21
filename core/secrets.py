"""API keys in Windows Credential Manager via keyring (docs/PROJECT_RULES.md rule 7).

Keys are never written to files, logs or the database. The UI only ever sees
a masked form (last 4 characters).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

SERVICE = "Nightglass"


@dataclass(frozen=True)
class KeySpec:
    name: str        # keyring user name, e.g. "haveibeenpwned"
    title: str
    hint: str        # shown when the key is not set


KNOWN_KEYS = [
    KeySpec("haveibeenpwned", "Have I Been Pwned", "Needed for BreachChecker (paid API key)"),
    KeySpec("ipinfo", "ipinfo", "Optional · raises the free-tier limits for IPLocation"),
    KeySpec("github", "GitHub token", "Optional · raises the rate limit for GitHubRecon"),
]

#: The owner's own Instagram login for Osintgram: one keyring entry holding {"username", "password"}.
INSTAGRAM_LOGIN = KeySpec("instagram_login", "Instagram account (for Osintgram)",
                          "Your own login, used only by Osintgram runs. Instagram may block or ban it.")


class KeyStore:
    def __init__(self, backend=None):
        if backend is None:
            import keyring

            backend = keyring.get_keyring()
        self._backend = backend

    def get(self, name: str) -> str | None:
        try:
            return self._backend.get_password(SERVICE, name)
        except Exception:  # a broken credential store must not crash the app
            return None

    def has(self, name: str) -> bool:
        return bool(self.get(name))

    def set(self, name: str, value: str) -> None:
        value = value.strip()
        if not value or any(c.isspace() for c in value) or len(value) > 512:
            raise ValueError("That doesn't look like an API key (no spaces, max 512 characters).")
        try:
            self._backend.set_password(SERVICE, name, value)
        except Exception as exc:  # a locked or broken credential store: shown in the key dialog, not a crash
            raise ValueError(f"Windows Credential Manager did not save the key ({type(exc).__name__}).") from exc

    def set_login(self, name: str, username: str, password: str) -> None:
        """A username + password pair (passwords may contain spaces, so set() can't hold them)."""
        from core.validation import TargetType, ValidationError, validate_target

        try:
            username = validate_target(TargetType.USERNAME, username.strip().lstrip("@"))
        except ValidationError as exc:
            raise ValueError(f"Username: {exc}") from None
        if not password or len(password) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in password):
            raise ValueError("Enter the password (no line breaks, max 512 characters).")
        try:
            self._backend.set_password(SERVICE, name, json.dumps({"username": username, "password": password}))
        except Exception as exc:
            raise ValueError(f"Windows Credential Manager did not save the login ({type(exc).__name__}).") from exc

    def login(self, name: str) -> tuple[str, str] | None:
        return parse_login(self.get(name))

    def delete(self, name: str) -> None:
        try:
            self._backend.delete_password(SERVICE, name)
        except Exception:
            pass

    def masked(self, name: str) -> str | None:
        value = self.get(name)
        return None if not value else "•" * 12 + " " + value[-4:]


def parse_login(value: str | None) -> tuple[str, str] | None:
    """(username, password) from a stored login entry, or None."""
    try:
        data = json.loads(value or "")
        return (data["username"], data["password"]) if data.get("username") and data.get("password") else None
    except (ValueError, TypeError, AttributeError, KeyError):
        return None


class MemoryKeyring:
    """In-memory backend for tests."""

    def __init__(self):
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, name: str) -> str | None:
        return self.store.get((service, name))

    def set_password(self, service: str, name: str, value: str) -> None:
        self.store[(service, name)] = value

    def delete_password(self, service: str, name: str) -> None:
        self.store.pop((service, name), None)
