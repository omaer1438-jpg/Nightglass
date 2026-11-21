"""WP1 hardening: data-dir override, single instance, crash log, redirects, key store, cache cleanup."""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

from core import net, paths
from core.net import ApiCache, Http, NetError
from core.secrets import KeyStore


def test_relative_data_dir_override_is_made_absolute(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(paths.DATA_DIR_ENV, "data_all")
    assert paths.data_dir() == tmp_path / "data_all" and paths.data_dir().is_absolute()


@pytest.mark.skipif(sys.platform != "win32", reason="the lock uses msvcrt")
def test_second_instance_cannot_take_the_lock():
    from app.__main__ import _single_instance_lock

    first = _single_instance_lock()
    assert first is not None
    try:
        assert _single_instance_lock() is None
    finally:
        first.close()
    again = _single_instance_lock()  # released when the holder closes or exits
    assert again is not None
    again.close()


def test_uncaught_exceptions_reach_the_crash_log(monkeypatch):
    import faulthandler

    from app.__main__ import _enable_crash_log

    previous = []
    monkeypatch.setattr(sys, "excepthook", lambda *exc: previous.append(exc))  # stands in for pytest-qt's hook
    monkeypatch.setattr(faulthandler, "enable", lambda file: None)
    _enable_crash_log()
    try:
        raise RuntimeError("example failure in a slot")
    except RuntimeError:
        sys.excepthook(*sys.exc_info())
    assert "example failure in a slot" in (paths.data_dir() / "crash.log").read_text(encoding="utf-8")
    assert len(previous) == 1  # still shown on a console when there is one


def test_self_check_needs_every_module_number():
    from app.__main__ import self_check  # noqa: F401  (imports cleanly)
    from core.modules import discover

    numbers = [int(m.number) for m in discover()]
    assert numbers == list(range(1, len(numbers) + 1))


# ---------------------------------------------------------------- redirects


def redirecting_client(seen: list, location: str) -> Http:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "example.com":
            return httpx.Response(302, headers={"location": location})
        return httpx.Response(200, json={"ok": True})

    return Http(ApiCache(None, False), transport=httpx.MockTransport(handler))


def test_key_headers_are_not_sent_to_another_host(monkeypatch):
    monkeypatch.setattr(net, "_is_internal", lambda host: False)
    seen: list[httpx.Request] = []
    http = redirecting_client(seen, "https://example.net/next")
    http.request("example", "https://example.com/api", headers={"hibp-api-key": "example-key"})
    assert seen[0].headers.get("hibp-api-key") == "example-key"
    assert seen[1].url.host == "example.net" and "hibp-api-key" not in seen[1].headers


@pytest.mark.parametrize("location", ["http://127.0.0.1/admin", "http://192.168.0.1/", "http://169.254.169.254/",
                                      "http://[::1]/", "http://192.0.2.10/"])
def test_redirects_to_internal_addresses_are_refused(location):
    seen: list[httpx.Request] = []
    http = redirecting_client(seen, location)
    with pytest.raises(NetError, match="private or local"):
        http.request("web", "https://example.com/")
    assert len(seen) == 1  # the internal address was never contacted


# ---------------------------------------------------------------- keys and cache


def test_a_broken_credential_store_is_a_user_message():
    class Locked:
        def set_password(self, *args):
            raise PermissionError("access denied")

    with pytest.raises(ValueError, match="Credential Manager"):
        KeyStore(Locked()).set("github", "example-token-1234")


def test_deleting_a_case_clears_cached_provider_answers(db, manager, new_case, tmp_path):
    from core.retention import delete_case

    case = manager.create_case(new_case())
    cache = ApiCache(Path(db.path), True)
    cache.put("rdap", "k1", {"body": {"name": "example.com"}})
    assert cache.get("rdap", "k1") is not None
    delete_case(db, case.id, tmp_path / "data")
    assert cache.get("rdap", "k1") is None


def test_hard_exit_ends_the_process_with_its_code_and_no_fault(tmp_path):
    import subprocess
    import sys

    code = ("import faulthandler, sys; faulthandler.enable(file=open(sys.argv[1], 'w')); "
            "from app.__main__ import _hard_exit; _hard_exit(3)")
    log = tmp_path / "crash.log"
    root = Path(__file__).resolve().parent.parent
    done = subprocess.run([sys.executable, "-c", code, str(log)], cwd=root, timeout=60)
    assert done.returncode == 3
    assert log.read_text(encoding="utf-8") == ""
