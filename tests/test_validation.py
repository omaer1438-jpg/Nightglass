import pytest

from core.validation import TargetType, ValidationError, detect_type, fingerprint, validate_target


@pytest.mark.parametrize(
    "kind, raw, expected",
    [
        ("username", "example_user", "example_user"),
        ("username", "@example_user", "example_user"),
        ("email", "Example_User@Example.COM", "Example_User@example.com"),
        ("phone", "+1 555 010 0123", "+15550100123"),
        ("phone", "001-555-010-0123", "+15550100123"),
        ("ip", "192.0.2.10", "192.0.2.10"),
        ("ip", "2001:DB8::1", "2001:db8::1"),
        ("domain", "Sub.Example.com.", "sub.example.com"),
        ("url", "HTTPS://Example.com/Path?q=1", "https://example.com/Path?q=1"),
        ("url", "http://203.0.113.5:8080/", "http://203.0.113.5:8080/"),
        ("other", "  free text note  ", "free text note"),
    ],
)
def test_valid_inputs_are_normalized(kind, raw, expected):
    assert validate_target(kind, raw) == expected


@pytest.mark.parametrize(
    "kind, raw",
    [
        ("username", ""),
        ("username", "-rf"),            # would look like a CLI flag
        ("username", "example user"),
        ("username", "example_user; rm"),
        ("email", "not-an-email"),
        ("email", "-x@example.com"),
        ("email", "a@@example.com"),
        ("phone", "555 010 0123"),      # no country code
        ("phone", "+0 555 010"),
        ("ip", "192.0.2.300"),
        ("ip", "fe80::1%x?a=b#c"),     # IPv6 zone id: free text inside request URLs
        ("url", "http://[fe80::1%25eth0]/"),
        ("domain", "localhost"),
        ("domain", "-bad.example.com"),
        ("domain", "example.123"),
        ("url", "ftp://example.com"),
        ("url", "javascript:alert(1)"),
        ("url", "https://user:pass@example.com"),
        ("url", "https://exa mple.com"),
        ("other", "line\nbreak"),
        ("other", "x" * 300),
    ],
)
def test_invalid_inputs_are_rejected(kind, raw):
    with pytest.raises(ValidationError):
        validate_target(kind, raw)


def test_file_must_exist(tmp_path):
    sample = tmp_path / "profile_01.png"
    sample.write_bytes(b"fake")
    assert validate_target("file", str(sample)) == str(sample.resolve())
    with pytest.raises(ValidationError):
        validate_target("file", str(tmp_path / "missing.png"))


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("example_user", TargetType.USERNAME),
        ("owner@example.com", TargetType.EMAIL),
        ("+1 555 010 0123", TargetType.PHONE),
        ("198.51.100.7", TargetType.IP),
        ("example.com", TargetType.DOMAIN),
        ("https://example.com/a", TargetType.URL),
        ("not valid at all!", None),
        ("", None),
    ],
)
def test_detect_type(raw, expected):
    assert detect_type(raw) == expected


def test_fingerprint_depends_on_type_and_value():
    a = fingerprint("username", "example_user")
    assert len(a) == 64
    assert a == fingerprint(TargetType.USERNAME, "example_user")
    assert a != fingerprint("domain", "example_user")
