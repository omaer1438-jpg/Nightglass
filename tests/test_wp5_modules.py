"""WP5: phone app-registration check (ignorant), InstagramPage, ImageMeta dHash and the Settings rows.
Fake data only: example_user, +1 555 numbers, example.com. Mocked HTTP; nothing is sent."""

from __future__ import annotations

import json
import re

import pytest
from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import QColor, QImage, QPainter

from adapters import exiftool, ignorant, instagrampage
from core.catalog import load_catalog
from core.cases import LookupMode
from core.modules import check_gates, discover, engines, module_status, pick_engine
from core.net import NetError
from core.secrets import INSTAGRAM_LOGIN, KeyStore, MemoryKeyring
from core.validation import TargetType
from tests.test_adapters_net import ctx_for, no_rate_limits  # noqa: F401  (autouse fixture)


def spec(module_id):
    return next(m for m in discover() if m.id == module_id)


# ---------------------------------------------------------------- phone app-registration (ignorant)

IGNORANT_OUTPUT = """\
Twitter : @palenath
****************
   +1 5550100
****************
[+] instagram.com
[-] snapchat.com
[x] amazon.com

[+] Phone number used, [-] Phone number not used, [x] Rate limit
3 websites checked in 0.73 seconds""".splitlines()


def test_ignorant_parse_found_not_found_and_not_checked():
    result = ignorant.parse(IGNORANT_OUTPUT)
    found = [f for f in result.findings if f.result.value == "found"]
    assert [f.value for f in found] == ["instagram.com"]
    assert "not proof" in found[0].notes
    assert any(f.result.value == "uncertain" and "amazon.com" in f.title for f in result.findings)
    assert result.counts == {"found": 1, "not_found": 1, "not_checked": 1, "checked": 3}


def test_ignorant_nothing_checked_is_a_failed_run():
    with pytest.raises(ValueError, match="None of the 3 sites"):
        ignorant.parse(["[x] amazon.com", "[x] instagram.com", "[x] snapchat.com"])
    with pytest.raises(ValueError, match="no site results"):
        ignorant.parse(["Traceback (most recent call last):"])


@pytest.mark.parametrize("number, split", [
    ("+15550100", ("1", "5550100")),
    ("+447700900123", ("44", "7700900123")),
    ("+380441234567", ("380", "441234567")),
    ("+74951234567", ("7", "4951234567")),
    ("+97142345678", ("971", "42345678")),
])
def test_ignorant_manifest_splits_the_country_code(number, split):
    code = load_catalog().get("ignorant").launch.args[1]
    pattern = re.search(r'r"(.+?)", sys\.argv', code)[1]
    assert re.match(pattern, number).groups() == split


def test_phone_registration_is_off_by_default_and_fully_gated(db, manager, new_case):
    phone = spec("phoneregistration")
    keys = KeyStore(MemoryKeyring())
    catalog = load_catalog()
    assert phone.is_active and phone.active_setting == "active.phone_registration"
    assert db.get_setting("active.phone_registration") is False
    assert module_status(phone, catalog, db, keys.has).label == "Off"
    assert pick_engine(phone, catalog, db, keys.has) is None

    db.set_setting("active.phone_registration", True)
    engine = next(e for e in engines(phone, catalog, db, keys.has) if e.id == "ignorant")
    assert engine.is_active and engine.is_external
    passive_case = manager.create_case(new_case(first_target_type=None, first_target_value=""))
    problems = check_gates(phone, passive_case, TargetType.PHONE, "+15550100", db, engine)
    assert any("does not allow active" in p for p in problems) and any("not named" in p for p in problems)
    active_case = manager.create_case(new_case(authorized_scope="My own phone +15550100",
                                               allowed_modes=[LookupMode.LOCAL, LookupMode.ACTIVE],
                                               first_target_type=None, first_target_value=""))
    assert check_gates(phone, active_case, TargetType.PHONE, "+15550100", db, engine) == []
    assert check_gates(phone, active_case, TargetType.PHONE, "+15550199", db, engine)  # not in scope


# ---------------------------------------------------------------- InstagramPage

PROFILE_PAGE = """<html><head>
<meta property="og:type" content="profile" />
<meta property="og:image" content="https://example.com/pic.jpg?a=1&amp;b=2" />
<meta property="og:title" content="Example User (&#064;example_user) &#x2022; Instagram photos and videos" />
<meta property="og:description" content="1,234 Followers, 56 Following, 78 Posts - See Instagram photos and videos from Example User (&#064;example_user)" />
<meta content="1,234 Followers, 56 Following, 78 Posts - Example User (&#064;example_user) on Instagram: &quot;Fake bio &#x2728;&quot;" name="description" />
</head></html>"""


def test_instagrampage_reads_the_public_meta_tags():
    url = "https://www.instagram.com/example_user/"
    ctx, lines = ctx_for("username", "example_user", {url: (200, PROFILE_PAGE.encode(), None)})
    findings = instagrampage.run(ctx)
    values = {f.title: f.value for f in findings}
    assert values["Instagram profile"] == url and findings[0].result.value == "found"
    assert values["Instagram: Name"] == "Example User"
    assert (values["Instagram: Followers"], values["Instagram: Following"], values["Instagram: Posts"]) == \
        ("1,234", "56", "78")
    assert values["Instagram: Bio"] == "Fake bio ✨"
    assert values["Instagram: Profile picture"] == "https://example.com/pic.jpg?a=1&b=2"
    assert instagrampage.MODULE.is_external and not instagrampage.MODULE.is_active


def test_instagrampage_login_wall_fails_with_a_clear_reason():
    login_page = b"<html><head><meta property='og:title' content='Login'></head></html>"
    ctx, _ = ctx_for("username", "example_user", {
        "https://www.instagram.com/example_user/": (302, b"", {"location": "https://www.instagram.com/accounts/login/"}),
        "https://www.instagram.com/accounts/login/": (200, login_page, None),
    })
    with pytest.raises(ValueError, match="Instagram asked for a login; try Osintgram"):
        instagrampage.run(ctx)
    ctx, _ = ctx_for("username", "example_user",
                     {"https://www.instagram.com/example_user/": (200, b"<html>no meta</html>", None)})
    with pytest.raises(ValueError, match="asked for a login"):
        instagrampage.run(ctx)


def test_instagrampage_missing_profile():
    ctx, _ = ctx_for("username", "example_user", {"https://www.instagram.com/example_user/": (404, b"", None)})
    with pytest.raises(NetError, match="no public profile"):
        instagrampage.run(ctx)


# ---------------------------------------------------------------- ImageMeta dHash


def _picture(width: int, height: int, flip: bool = False) -> QImage:
    image = QImage(320, 240, QImage.Format.Format_RGB32)
    image.fill(QColor("#203040"))
    painter = QPainter(image)
    for i in range(8):
        shade = 30 * i if not flip else 240 - 30 * i
        painter.fillRect(QRect(i * 40, (i * 23) % 200, 40, 60 + i * 5), QColor(shade, 255 - shade, (i * 70) % 255))
    painter.fillRect(QRect(200 if not flip else 20, 30, 90, 90), QColor("#f0f0f0"))
    painter.end()
    return image.scaled(width, height, Qt.AspectRatioMode.IgnoreAspectRatio,
                        Qt.TransformationMode.SmoothTransformation)


def _distance(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def test_dhash_matches_resized_copies_and_separates_other_images(qapp, tmp_path):
    original, small, other = tmp_path / "a.png", tmp_path / "a_small.jpg", tmp_path / "b.png"
    assert _picture(320, 240).save(str(original))
    assert _picture(160, 120).save(str(small), "JPG", 85)
    assert _picture(320, 240, flip=True).save(str(other))
    a, b, c = exiftool.dhash(original), exiftool.dhash(small), exiftool.dhash(other)
    assert re.fullmatch(r"[0-9a-f]{16}", a)
    assert _distance(a, b) <= 4
    assert _distance(a, c) > 10
    (tmp_path / "broken.png").write_bytes(b"not an image")
    assert exiftool.dhash(tmp_path / "broken.png") is None


def test_imagemeta_emits_the_dhash_finding(qapp, tmp_path):
    picture = tmp_path / "photo.png"
    _picture(320, 240).save(str(picture))
    record = [{"SourceFile": str(picture), "File:FileType": "PNG"}]
    result = exiftool.parse(json.dumps(record).splitlines(), tmp_path, str(picture))
    by_title = {f.title: f for f in result.findings}
    assert by_title["Perceptual hash (dHash)"].value == f"dhash:{exiftool.dhash(picture)}"
    assert by_title["Perceptual hash (dHash)"].result.value == "info"


# ---------------------------------------------------------------- Settings


@pytest.fixture
def settings_screen(qtbot, db):
    from app.screens.settings import SettingsScreen
    from app.state import AppState

    state = AppState(db, keys=KeyStore(MemoryKeyring()))
    screen = SettingsScreen(state)
    qtbot.addWidget(screen)
    return screen, state


def test_phone_switch_is_selectable_and_asks_first(settings_screen, monkeypatch):
    from app.dialogs import Notice

    screen, state = settings_screen
    assert screen.phone.isEnabled() and not screen.phone.isChecked()

    def confirm(self):
        self.action_taken = True
        return 1
    monkeypatch.setattr(Notice, "exec", confirm)
    screen.phone.setChecked(True)
    assert state.db.get_setting("active.phone_registration") is True


def test_instagram_login_row_saves_masks_and_removes(settings_screen, monkeypatch):
    from app.screens.settings import InstagramLoginDialog

    screen, state = settings_screen
    assert not screen.instagram_remove.isVisibleTo(screen)

    def fill(self):
        self.username.setText("@example_user")
        self.password.setText("fake pass phrase 1")
        return 1
    monkeypatch.setattr(InstagramLoginDialog, "exec", fill)
    screen.edit_instagram()
    assert state.keys.login(INSTAGRAM_LOGIN.name) == ("example_user", "fake pass phrase 1")
    text = screen.instagram_row.description.text()
    assert "example_user" in text and "fake pass" not in text
    assert screen.instagram_remove.isVisibleTo(screen)
    screen.remove_instagram()
    assert state.keys.login(INSTAGRAM_LOGIN.name) is None


def test_keystore_login_validation():
    keys = KeyStore(MemoryKeyring())
    with pytest.raises(ValueError, match="Username"):
        keys.set_login(INSTAGRAM_LOGIN.name, "not a user!", "fake-pass")
    with pytest.raises(ValueError, match="password"):
        keys.set_login(INSTAGRAM_LOGIN.name, "example_user", "line\nbreak")
    assert not keys.has(INSTAGRAM_LOGIN.name)
