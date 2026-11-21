"""Module registry, gates, scope checks and the Sherlock / ExifTool adapters."""

from __future__ import annotations

import json

import pytest

from adapters import exiftool as exif_adapter
from adapters import sherlock as sherlock_adapter
from core.cases import LookupMode
from core.findings import ResultKind
from core.modules import ModuleSpec, check_gates, discover, scope_covers
from core.paths import PROJECT_ROOT
from core.validation import TargetType

SHERLOCK_OUTPUT = """\
[*] Checking username example_user on:

[+] GitHub: https://github.com/example_user
[+] Reddit: https://www.reddit.com/user/example_user
[-] Pinterest: Not Found!
[-] Instagram: Blocked by bot detection (proxy may help)
[-] Tumblr: Not Found!
[-] Site X: Illegal Username Format For This Site!
[-] Odd Site: Connection error
[+] GitHub: https://github.com/example_user
[*] Search completed with 2 results
""".splitlines()


def test_discover_finds_adapters():
    ids = [m.id for m in discover()]
    assert "userrecon" in ids and "imagemeta" in ids
    numbers = [m.number for m in discover()]
    assert numbers == sorted(numbers) and len(set(numbers)) == len(numbers)


def test_sherlock_parse():
    result = sherlock_adapter.parse(SHERLOCK_OUTPUT)
    assert result.counts == {"found": 2, "uncertain": 2, "not_found": 2}
    found = [f for f in result.findings if f.result is ResultKind.FOUND]
    assert [(f.title, f.url) for f in found] == [
        ("GitHub profile", "https://github.com/example_user"),
        ("Reddit profile", "https://www.reddit.com/user/example_user"),
    ]
    assert all("Not proof" in f.notes for f in found)
    assert sherlock_adapter.console_tag("[+] GitHub: https://github.com/example_user") == "g"
    assert sherlock_adapter.console_tag("[-] Pinterest: Not Found!") == "p"
    assert sherlock_adapter.console_tag("[-] Instagram: Blocked by bot detection") == "b"


EXIF_JSON = [{
    "SourceFile": "C:/cases/profile_01.jpg",
    "File:FileType": "JPEG",
    "Composite:ImageSize": "64 48",
    "IFD0:Make": "ExampleCam",
    "IFD0:Model": "Model X",
    "IFD0:Software": "ExampleEdit",
    "ExifIFD:DateTimeOriginal": "2026:10:29 21:58:00",
    "Composite:GPSLatitude": 51.5,
    "Composite:GPSLongitude": -0.12,
}]


def test_exiftool_parse(tmp_path):
    sample = tmp_path / "profile_01.jpg"
    sample.write_bytes(b"fake")
    lines = json.dumps(EXIF_JSON, indent=1).splitlines()
    result = exif_adapter.parse(lines, tmp_path, str(sample))
    titles = {f.title: f.value for f in result.findings}
    assert titles["Camera make"] == "ExampleCam"
    assert titles["GPS location in metadata"] == "51.5, -0.12"
    assert len(titles["SHA-256"]) == 64
    assert result.counts["gps"] == 1

    no_gps = [{k: v for k, v in EXIF_JSON[0].items() if "GPS" not in k}]
    titles = {f.title for f in exif_adapter.parse(json.dumps(no_gps).splitlines()).findings}
    assert "No GPS data" in titles
    with pytest.raises(ValueError, match="File not found"):
        exif_adapter.parse(["Error: File not found - C:/missing.jpg"])


@pytest.mark.skipif(not (PROJECT_ROOT / "bin" / "exiftool.exe").is_file(), reason="ExifTool not installed")
def test_real_exiftool_round_trip(qtbot, tmp_path):
    from PySide6.QtGui import QColor, QImage

    from core.catalog import load_catalog
    from core.runner import ProcessJob, build_command

    image = QImage(32, 24, QImage.Format.Format_RGB32)
    image.fill(QColor("#4fd6c8"))
    sample = tmp_path / "profile 01 & co.jpg"  # spaces and & must stay one literal argument
    assert image.save(str(sample), "JPG")
    tool = load_catalog().get("exiftool")
    program, args = build_command(tool, "file", str(sample), tmp_path)
    job = ProcessJob(program, args, tmp_path, timeout_s=60, max_output_kb=2048)
    with qtbot.waitSignal(job.finished, timeout=60000) as blocker:
        job.start()
    outcome = blocker.args[0]
    assert outcome.status == "succeeded", outcome.error
    result = exif_adapter.parse(outcome.lines, tmp_path, str(sample))
    titles = {f.title: f.value for f in result.findings}
    assert titles["File type"] == "JPEG"
    assert "No GPS data" in titles


# ---------------------------------------------------------------- gates


@pytest.mark.parametrize(
    "scope, kind, value, expected",
    [
        ("My own domain example.com only.", TargetType.DOMAIN, "dev.example.com", True),
        ("My own domain example.com only.", TargetType.DOMAIN, "notexample.com", False),
        ("Lab network 192.0.2.0/24.", TargetType.IP, "192.0.2.10", True),
        ("Lab network 192.0.2.0/24.", TargetType.IP, "198.51.100.7", False),
        ("Host 203.0.113.5 only", TargetType.IP, "203.0.113.5", True),
        ("Profiles using example_user", TargetType.USERNAME, "example_user", True),
        ("https://example.com is mine", TargetType.URL, "https://shop.example.com/a", True),
        # whole-token matching (no substring hits)
        ("Host 192.0.2.10 only", TargetType.IP, "192.0.2.1", False),
        ("Host 192.0.2.1.", TargetType.IP, "192.0.2.1", True),
        ("Only www.example.com", TargetType.DOMAIN, "example.com", False),
        ("Domain notexample.com", TargetType.DOMAIN, "example.com", False),
        ("Domain example.com.au", TargetType.DOMAIN, "shop.example.com", False),
        ("Only shop.example.com", TargetType.DOMAIN, "example.com", False),
        ("Site example.co.uk", TargetType.DOMAIN, "other.co.uk", False),
        ("Mailbox bob@example.com", TargetType.EMAIL, "b@example.com", False),
        ("Mailbox admin@example.com", TargetType.EMAIL, "min@example.com", False),
        ("Mailbox admin@example.com.", TargetType.EMAIL, "admin@example.com", True),
        ("Profiles using example_user2", TargetType.USERNAME, "example_user", False),
    ],
)
def test_scope_covers(scope, kind, value, expected):
    assert scope_covers(scope, kind, value) is expected


ACTIVE = ModuleSpec(number="99", id="activetest", name="ActiveTest", icon="port", description="test",
                    labels=("active",), target_types=(TargetType.IP,), provider="the target host",
                    active_setting="active.port_scan", run=lambda ctx: [])


def test_gates(manager, new_case, db):
    case = manager.create_case(new_case(authorized_scope="My lab 192.0.2.0/24 and example.com"))
    userrecon = next(m for m in discover() if m.id == "userrecon")
    assert check_gates(userrecon, case, TargetType.USERNAME, "example_user", db) == []
    assert "accepts" in check_gates(userrecon, case, TargetType.EMAIL, "a@example.com", db)[0]

    local_only = manager.create_case(new_case(allowed_modes=[LookupMode.LOCAL]))
    assert "external" in check_gates(userrecon, local_only, TargetType.USERNAME, "example_user", db)[0]

    problems = check_gates(ACTIVE, case, TargetType.IP, "192.0.2.10", db)
    assert any("Settings" in p for p in problems)
    assert any("does not allow active" in p for p in problems)

    db.set_setting("active.port_scan", True)
    active_case = manager.create_case(new_case(
        authorized_scope="My lab 192.0.2.0/24", allowed_modes=[LookupMode.LOCAL, LookupMode.ACTIVE]))
    assert check_gates(ACTIVE, active_case, TargetType.IP, "192.0.2.10", db) == []
    assert "not named" in check_gates(ACTIVE, active_case, TargetType.IP, "198.51.100.7", db)[0]

    manager.close_case(active_case.id)
    assert "closed" in check_gates(ACTIVE, manager.get_case(active_case.id), TargetType.IP, "192.0.2.10", db)[0]
