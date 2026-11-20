"""ConfigGuard's DATABASE_URL pattern: a password in a URL of any scheme (#658).

The pattern named three schemes (postgres, mysql, mongodb), so a connection
string with a password under any other scheme was not reported: postgresql
(the SQLAlchemy and libpq name), postgresql+psycopg2, mongodb+srv, redis with
only a password, and the rest. It now reads the user and password after
"://", whatever comes before it, as one token, and reads out a port before a
path, a digest after the "@" and a placeholder of an exact shape. The three
schemes it named keep the reach they had.

The URLs are built when the tests run, not written out, so no scanner reads
this file as holding a credential.
"""

import json
import random
import re
import string
import time
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from qwed_new.guards.canonical_text import json_readings, reading_copies
from qwed_sdk.guards.config_guard import ConfigGuard

ROOT = Path(__file__).resolve().parent.parent
PATTERN = ConfigGuard.DEFAULT_SECRET_PATTERNS["DATABASE_URL"]
COMPILED = re.compile(PATTERN, re.IGNORECASE)
# The pattern before #658, for a caller who gives it back.
OLD_PATTERN = r"(postgres|mysql|mongodb)://[^:]+:[^@]+@"
# Generated, not written out, so no scanner reads it as a real password.
_RNG = random.Random(658)
PASSWORD = "".join(_RNG.choice(string.ascii_letters + string.digits) for _ in range(16))
HOST = "db.example.com:5432/prod"
# Joined to a scheme when the tests run, so this file holds no scheme,
# "://" and credential together for a scanner to read.
SEP = "://"


def _url(scheme="postgresql", user="admin", password=PASSWORD, host=HOST):
    return scheme + SEP + user + ":" + password + "@" + host


def _with(text, scheme="postgresql"):
    """_url() with *text* between the user's ":" and the "@"."""
    return _url(scheme, "admin", text)


def _found(text, guard=None):
    result = (guard or ConfigGuard()).scan_string(text)
    return {found["type"]: found["count"] for found in result.get("secrets_found", [])}


def _reported(text):
    return "DATABASE_URL" in _found(text)


def _tags(text):
    """*text* written in Unicode tag characters, which draw nothing."""
    return "".join(chr(0xE0000 + ord(c)) for c in text)


def test_the_values_have_the_shapes_the_tests_need():
    assert len(PASSWORD) == 16
    assert PASSWORD.isascii()
    assert PASSWORD.isalnum()


def test_the_issue_example_is_reported():
    result = ConfigGuard().scan_string("DATABASE_URL=" + _url())
    assert result["verified"] is False
    assert result["secrets_found"] == [
        {"type": "DATABASE_URL", "count": 1, "message": "Found 1 instance(s) of DATABASE_URL."}
    ]


SCHEMES = [
    "postgres", "postgresql", "postgresql+psycopg2", "postgresql+asyncpg", "mysql", "mysql+pymysql",
    "mariadb", "mariadb+mariadbconnector", "mssql", "mssql+pyodbc", "oracle+oracledb", "cockroachdb",
    "mongodb", "mongodb+srv", "redis", "rediss", "amqp", "amqps", "https", "http", "ftp", "sftp",
    "ssh", "git+ssh", "jdbc:postgresql", "jdbc:mysql", "snowflake", "clickhouse+native", "s3", "x-y.z",
    # Case.
    "POSTGRES", "POSTGRESQL", "PostgreSQL", "MONGODB+SRV", "Redis",
    # A scheme with a letter of another script, or wholly in one, is still
    # followed by the same password.
    "p\u043estgres",
    "\u03c1ostgres",
    "\u043f\u043e\u0441\u0442\u0433\u0440\u0435\u0441",
    "\uff50\uff4f\uff53\uff54\uff47\uff52\uff45\uff53",
    # No scheme at all.
    "",
]


@pytest.mark.parametrize("scheme", SCHEMES, ids=[ascii(s) for s in SCHEMES])
def test_any_scheme_is_reported(scheme):
    assert _found(_url(scheme)) == {"DATABASE_URL": 1}


REPORTED = {
    "empty user": _url("redis", ""),
    "rediss, empty user": _url("rediss", ""),
    "user with an at sign": _url(user="myadmin@myserver"),
    "user that is a placeholder": _url(user="<user>"),
    "user that is a variable": _url(user="${PG_USER}"),
    "password with a slash": _with("ab/cd+ef=="),
    "password with two slashes": _with("ab//cd"),
    "password with a question mark": _with("ab?cd"),
    "password with a hash": _with("ab#cd"),
    "password with a colon": _with("ab:cd"),
    "password with brackets": _with("[ab]"),
    "password of one character": _with("x"),
    "password starting with a dollar sign": _with("$ecret"),
    "dollar variable without braces": _with("$PG_PASSWORD"),
    "variable with a default": _with("${PG_PASSWORD:-" + PASSWORD + "}"),
    "variable with an error message": _with("${PG_PASSWORD:?unset}"),
    "variable then a literal": _with("${PG}" + PASSWORD),
    "literal then a variable": _with(PASSWORD + "${PG}"),
    "two variables": _with("${A}${B}"),
    "empty braces": _with("${}"),
    "variable starting with a digit": _with("${1PG}"),
    "variable with a hyphen": _with("${PG-PASSWORD}"),
    "format field": _with("{password}"),
    "printf field": _with("%s"),
    "empty angle brackets": _with("<>"),
    "angle brackets around a dotted name": _with("<a.b>"),
    "stars then text": _with("***x"),
    "text then stars": _with("x***"),
    "six digits before a slash": _with("123456/ab"),
    "zeros and digits before a slash": _with("000443/ab"),
    "password starting with a slash": _with("/ab+cd=="),
    "password starting with a question mark": _with("?ab"),
    "digits right before the at sign": _url("postgresql", "db.example.com", "5432", "x"),
    "digits, a letter, then a slash": _with("5432a/b"),
    "long password": _with("a" * 10_000),
    "IPv6 host": _url(host="[::1]:5432/db"),
    "no host": _url(host=""),
    "in double quotes": '"' + _url() + '"',
    "in single quotes": "'" + _url() + "'",
    "in JSON": json.dumps({"database": {"url": _url()}}),
    "in minified JSON": json.dumps({"database": {"url": _url()}}, separators=(",", ":")),
    "in YAML": "database:\n  url: " + _url() + "\n",
    "in an env file": "DATABASE_URL=" + _url() + "\n",
    "in a markdown link": "[db](" + _url() + ")",
    "glued after a word": "x" + _url(),
    "after a jdbc prefix": "jdbc:" + _url("mysql"),
    "in a SQLAlchemy call": "create_engine('" + _url("postgresql+psycopg2") + "')",
    "after a URL with a port": "redis://localhost:6379 " + _url(),
}


@pytest.mark.parametrize("name", list(REPORTED))
def test_a_password_in_any_form_is_reported(name):
    assert _reported(REPORTED[name])


def test_each_url_is_counted_once_under_one_type():
    text = " ".join([_url(), _url("redis", ""), _url("https", "u", PASSWORD, "github.com"), _url()])
    assert _found(text) == {"DATABASE_URL": 4}


# A placeholder of an exact shape, in ASCII, as the whole password.
PLACEHOLDERS = {
    "dollar-brace variable": "${PG_PASSWORD}",
    "lower-case variable": "${pg_password}",
    "one-letter variable": "${P}",
    "underscore variable": "${_}",
    "angle-bracket placeholder": "<password>",
    "angle-bracket placeholder with a hyphen": "<db-password>",
    "angle-bracket placeholder in capitals": "<POSTGRES_PASSWORD>",
}


@pytest.mark.parametrize("scheme", ["postgresql", "postgres", "MySQL", "mongodb"])
@pytest.mark.parametrize("name", list(PLACEHOLDERS))
def test_a_placeholder_password_is_read_out(name, scheme):
    assert not _reported(_with(PLACEHOLDERS[name], scheme))


# A run of "*" stays reported: a masked password has that shape, but so can
# a literal one, which the pattern before #658 reported too.
STARS = {
    "one star": "*",
    "three stars": "***",
    "eight stars": "*" * 8,
    "many stars": "*" * 100,
    "full-width stars": "＊" * 3,
    "small stars": "﹡" * 3,
}


@pytest.mark.parametrize("scheme", ["postgresql", "postgres", "MySQL", "mongodb", "https"])
@pytest.mark.parametrize("name", list(STARS))
def test_a_password_of_only_stars_is_reported(name, scheme):
    assert _reported(_with(STARS[name], scheme))


def test_a_password_of_only_stars_was_reported_before():
    assert "DATABASE_URL" in _found(_with("***", "postgres"), ConfigGuard(custom_patterns=OLD_GUARD_PATTERNS))


def test_placeholders_everywhere_are_read_out():
    assert not _reported(_url("postgresql", "<user>", "<password>", "<host>:5432/<db>"))


# A port before a path, query or fragment: the "@" is not in the userinfo.
PORTS = {
    "npm scope after a port": _url("http", "localhost", "4873/", "scope/pkg/-/pkg-1.0.0.tgz"),
    "path with an at sign": _url("https", "example.com", "8443/users/me", "v2"),
    "query with an email": _url("https", "example.com", "8443?login_hint=a", "example.com"),
    "fragment with an at sign": _url("https", "example.com", "8443#a", "b"),
    "one-digit port": _url("http", "h", "1/", "x"),
    "five-digit port": _url("http", "h", "65535/", "x"),
}


@pytest.mark.parametrize("name", list(PORTS))
def test_a_port_before_a_path_is_read_out(name):
    assert not _reported(PORTS[name])


@pytest.mark.parametrize("digits, reported", [(1, False), (5, False), (6, True)], ids=["1", "5", "6"])
def test_a_port_has_at_most_five_digits(digits, reported):
    assert _reported(_url("https", "example.com", "8" * digits + "/path", "x")) is reported


# Kept as false positives: a port of six digits or more, or none, before a
# path with an "@" reads the same as a password that starts with digits or
# "/", which SQLAlchemy reads as the password (see REPORTED).
@pytest.mark.parametrize("port", ["000443", "123456", ""], ids=["leading zeros", "six digits", "empty"])
def test_a_longer_or_empty_port_stays_reported(port):
    assert _reported(_url("https", "example.com", port + "/users/me", "v2"))


SHA256 = "".join(_RNG.choice("0123456789abcdef") for _ in range(64))
SHA512 = "".join(_RNG.choice("0123456789abcdef") for _ in range(128))

# An image pinned by a digest: what follows the "@" is no host and port.
DIGESTS = {
    "docker action pinned by digest": "uses: docker" + SEP + "alpine:3.18@sha256:" + SHA256,
    "quoted": 'uses: "docker' + SEP + 'node:20-alpine@sha256:' + SHA256 + '"',
    "with a comment after": "uses: docker" + SEP + "alpine:3.18@sha256:" + SHA256 + "  # v3.18\n",
    "oci reference": "oci" + SEP + "registry.example.com/app:1.2@sha512:" + SHA512,
    "upper-case digest": "docker" + SEP + "alpine:3.18@SHA256:" + SHA256.upper(),
}


@pytest.mark.parametrize("name", list(DIGESTS))
def test_an_image_pinned_by_digest_is_read_out(name):
    assert ConfigGuard().scan_string(DIGESTS[name])["verified"] is True


# A digest of the wrong length, glued to more text, or in another script is
# not that shape; a host named sha256 with a port is a host.
NOT_DIGESTS = {
    "63 hex": "docker" + SEP + "alpine:3.18@sha256:" + SHA256[:63],
    "65 hex": "docker" + SEP + "alpine:3.18@sha256:" + SHA256 + "a",
    "digest glued to a letter": "docker" + SEP + "alpine:3.18@sha256:" + SHA256 + "g",
    "digest then a path": "docker" + SEP + "alpine:3.18@sha256:" + SHA256 + "/x",
    "wrong algorithm length": "docker" + SEP + "alpine:3.18@sha512:" + SHA256,
    "host named sha256 with a port": "x" + SEP + "admin:" + PASSWORD + "@sha256:5432/db",
    "Cyrillic a in the label": "docker" + SEP + "alpine:3.18@sh\u0430256:" + SHA256,
    "full-width digits": "docker" + SEP + "alpine:3.18@sha256:" + "\uff11" * 64,
}


@pytest.mark.parametrize("name", list(NOT_DIGESTS))
def test_a_near_digest_is_still_reported(name):
    assert _reported(NOT_DIGESTS[name])


NOT_CREDENTIALS = {
    "empty password": _with(""),
    "no password": "postgresql://admin@" + HOST,
    "no userinfo": "postgresql://" + HOST,
    "no scheme separator": "admin:" + PASSWORD + "@" + HOST,
    "sqlite file": "sqlite:///./qwed.db",
    "empty text": "",
    "email after a URL on the next line": "postgresql://db.example.com/prod\nadmin_email: a@example.com",
    "minified JSON: a URL with a port, then an email": json.dumps(
        {"redis": "redis://localhost:6379", "email": "a@example.com"}, separators=(",", ":")
    ),
    "IPv6 host, a port, then a path at sign": "http://[::1]" + ":8080/@x",
    "GitHub expression with spaces": "postgresql://qwed:${{ env.PG_PASSWORD }}@localhost:5432/qwed_db",
}


@pytest.mark.parametrize("name", list(NOT_CREDENTIALS))
def test_text_without_a_password_in_a_url_passes(name):
    assert ConfigGuard().scan_string(NOT_CREDENTIALS[name])["verified"] is True


# A user and password the one-token reading ends early: whitespace or a
# quote character inside, a user holding "/", "?", "#", "[" or "]", a
# password holding "://" or starting with a port before a path.
SPLIT = {
    "space in the password": ("admin", "ab cd"),
    "space before the at sign": ("admin", PASSWORD + " "),
    "space after the colon": ("admin", " " + PASSWORD),
    "tab in the password": ("admin", "ab\tcd"),
    "newline in the password": ("admin", "ab\ncd"),
    "no-break space in the password": ("admin", "ab\u00a0cd"),
    "space in the user": ("my user", PASSWORD),
    "double quote in the password": ("admin", 'ab"cd'),
    "single quote in the password": ("admin", "ab'cd"),
    "backtick in the password": ("admin", "ab`cd"),
    "slash in the user": ("a/b", PASSWORD),
    "question mark in the user": ("a?b", PASSWORD),
    "hash in the user": ("a#b", PASSWORD),
    "brackets in the user": ("[a]", PASSWORD),
    "password holding a scheme separator": ("admin", "ab://cd"),
    "password starting with a port shape": ("admin", "5432/cd"),
}
OLD_GUARD_PATTERNS = {"DATABASE_URL": OLD_PATTERN}


@pytest.mark.parametrize("scheme", ["postgres", "mysql", "mongodb", "POSTGRES", "mysql+pymysql"])
@pytest.mark.parametrize("name", list(SPLIT))
def test_the_schemes_named_before_keep_their_reach(name, scheme):
    url = _url(scheme, *SPLIT[name])
    assert _reported(url)
    assert "DATABASE_URL" in _found(url, ConfigGuard(custom_patterns=OLD_GUARD_PATTERNS))


@pytest.mark.parametrize("scheme", ["postgresql", "mongodb+srv", "redis", "https"])
@pytest.mark.parametrize("name", list(SPLIT))
def test_other_schemes_read_a_url_as_one_token(name, scheme):
    # Knowingly out of scope: the pattern did not report these schemes
    # before, and reading them across whitespace and quotes would report
    # prose and JSON lines (see NOT_CREDENTIALS).
    url = _url(scheme, *SPLIT[name])
    assert not _reported(url)
    assert "DATABASE_URL" not in _found(url, ConfigGuard(custom_patterns=OLD_GUARD_PATTERNS))


def test_the_schemes_named_before_still_read_across_lines():
    # As before #658, an "@" on a later line ends the password.
    assert _reported("postgres" + SEP + "db.example.com/prod\nadmin_email: a@example.com")


def test_a_password_holding_a_scheme_named_before_is_out_of_scope():
    # The one form the three schemes lose: their password stops where the
    # next URL of the three starts, which keeps the search linear.
    url = _with("ab" + "mysql" + SEP + "cd", "postgres")
    assert not _reported(url)
    assert "DATABASE_URL" in _found(url, ConfigGuard(custom_patterns=OLD_GUARD_PATTERNS))


# Look-alikes that NFKC folds to ":", "/" or "@" are read as them; others are
# not punctuation a URL parser reads, so out of scope.
UNICODE_REPORTED = {
    "full-width colon and slashes": "postgresql\uff1a\uff0f\uff0fadmin:" + PASSWORD + "@h",
    "small colon": "postgresql\ufe55//admin:" + PASSWORD + "@h",
    "presentation-form colon": "postgresql\ufe13//admin:" + PASSWORD + "@h",
    "full-width at sign": "postgresql://admin:" + PASSWORD + "\uff20h",
    "small at sign": "postgresql://admin:" + PASSWORD + "\ufe6bh",
    "full-width colon between user and password": "postgresql://admin\uff1a" + PASSWORD + "@h",
    "Cyrillic letters in the password": _with("\u0440\u0430ss" + PASSWORD),
    "Greek letters in the password": _with("\u03c0\u03b1ss" + PASSWORD),
    "Kelvin sign in a placeholder name": _with("${\u212aEY}"),
    "Cyrillic letter in a placeholder name": _with("${PG_P\u0410SSWORD}"),
    "full-width placeholder": _with("\uff04\uff5bPG\uff5d"),
    "zero-width space inside a placeholder": _with("${PG\u200bPASSWORD}"),
    "tag characters as the separator": "postgresql" + _tags("://") + "admin:" + PASSWORD + "@h",
    "tag characters as the password": _with(_tags(PASSWORD)),
}


@pytest.mark.parametrize("name", list(UNICODE_REPORTED))
def test_unicode_forms_are_reported(name):
    assert _reported(UNICODE_REPORTED[name])


UNICODE_OUT_OF_SCOPE = {
    "ratio sign for the colon": "postgresql\u2236//admin:" + PASSWORD + "@h",
    "modifier letter colon": "postgresql\ua789//admin:" + PASSWORD + "@h",
    "division slashes": "postgresql:\u2215\u2215admin:" + PASSWORD + "@h",
    "fraction slashes": "postgresql:\u2044\u2044admin:" + PASSWORD + "@h",
}


@pytest.mark.parametrize("name", list(UNICODE_OUT_OF_SCOPE))
def test_lookalike_punctuation_nfkc_keeps_is_out_of_scope(name):
    assert not _reported(UNICODE_OUT_OF_SCOPE[name])


INVISIBLE = ["\u200b", "\u00ad", "\ufeff", "\u2060", "\u2800", "\u3164", chr(0x1C), chr(0x85), chr(0xE0041), "\u0307"]
# In _url(): inside "://", inside the user, before the user's ":", inside
# the password, before the "@".
POSITIONS = {"separator": 11, "user": 15, "before the colon": 18, "password": 25, "before the at sign": 35}


@pytest.mark.parametrize("position", list(POSITIONS))
@pytest.mark.parametrize("char", INVISIBLE, ids=[f"U+{ord(c):04X}" for c in INVISIBLE])
def test_an_invisible_character_inside_does_not_hide_it(char, position):
    url = _url()
    assert (url[10:13], url[18], url[35]) == ("://", ":", "@")
    at = POSITIONS[position]
    assert _reported(url[:at] + char + url[at:])


def test_a_custom_database_url_pattern_is_searched_as_written():
    guard = ConfigGuard(custom_patterns={"DATABASE_URL": OLD_PATTERN})
    assert "DATABASE_URL" not in _found(_url("postgresql"), guard)
    assert _found(_url("postgres"), guard) == {"DATABASE_URL": 1}


def test_a_custom_pattern_under_another_name_keeps_the_default():
    guard = ConfigGuard(custom_patterns={"INTERNAL_TOKEN": r"itk_[a-z0-9]{12}"})
    assert _found(_url(), guard) == {"DATABASE_URL": 1}


def test_an_escaped_json_url_is_read():
    # As sent, the text holds no "://" or "@"; its string does.
    text = '{"url": "' + _url().replace(":", "\\u003a").replace("@", "\\u0040") + '"}'
    assert "://" not in text
    assert "@" not in text
    assert json.loads(text) == {"url": _url()}
    assert _reported(text)


def test_an_escaped_json_placeholder_is_read_out():
    text = json.dumps({"url": _with("${PG_PASSWORD}"), "note": "a\tb"})
    assert "\\" in text
    assert ConfigGuard().scan_string(text)["verified"] is True


@pytest.mark.parametrize("config, path", [
    ({"database": {"url": _url()}}, "database.url"),
    ({"uses": _url()}, "uses"),
    ({"integrity": _url("redis", "")}, "integrity"),
    ({"urls": [_url("amqp")]}, "urls[0]"),
    ({"url": _url()[:20] + "\u200b" + _url()[20:]}, "url"),
], ids=["nested", "under uses", "under integrity", "in a list", "zero-width space inside"])
def test_a_tree_value_is_reported(config, path):
    violations = ConfigGuard().verify_config_safety(config)["violations"]
    assert [(v["type"], v["path"]) for v in violations] == [("DATABASE_URL", path)]


def test_a_tree_placeholder_passes():
    config = {"database": {"url": _with("${PG_PASSWORD}")}, "k8s": _url("postgresql", "<u>", "<p>")}
    assert ConfigGuard().verify_config_safety(config)["verified"] is True


def test_a_text_read_without_the_character_cache_is_read_the_same():
    # More distinct characters than canonical_text caches, so each is read
    # uncached; a guard used before keeps no state that changes the verdict.
    guard = ConfigGuard()
    assert guard.scan_string("warm " + "\u00e9" * 10)["verified"] is True
    many = "".join(chr(code) for code in range(0x4E00, 0x4E00 + 5_000))
    for text in (many + " " + _url(), _url() + "\u200b" + many):
        assert _found(text, guard) == {"DATABASE_URL": 1}
    assert guard.scan_string(_with("${PG}"))["verified"] is True


def _scan_secrets(monkeypatch, workspace):
    import action_entrypoint as entry

    outputs = {}
    monkeypatch.chdir(workspace)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.delenv("INPUT_OUTPUT_FORMAT", raising=False)
    monkeypatch.setattr(entry, "set_output", outputs.__setitem__)
    monkeypatch.setenv("INPUT_ACTION", "scan-secrets")
    monkeypatch.setenv("INPUT_FAIL_ON_FINDINGS", "true")
    monkeypatch.setenv("INPUT_PATHS", "**/*.env,**/*.yml")
    try:
        entry.main()
    except SystemExit as exc:
        return exc.code, outputs
    return 0, outputs


def test_the_action_fails_on_a_connection_string_and_passes_on_a_variable(monkeypatch, tmp_path):
    (tmp_path / "ci.yml").write_text("url: " + _with("${PG_PASSWORD}") + "\n")
    (tmp_path / "app.env").write_text("DATABASE_URL=" + _url() + "\n")
    exit_code, outputs = _scan_secrets(monkeypatch, tmp_path)
    assert (exit_code, outputs["findings_count"]) == (1, "1")

    (tmp_path / "app.env").write_text("DATABASE_URL=" + _with("${PG_PASSWORD}") + "\n")
    exit_code, outputs = _scan_secrets(monkeypatch, tmp_path)
    assert (exit_code, outputs["findings_count"], outputs["verdict"]) == (0, "0", "VERIFIED")


@pytest.mark.parametrize("name", [
    ".github/workflows/ci.yml",
    ".github/workflows/docker-images.yml",
    "deploy/kubernetes/secret.yaml",
    "deploy/.env.example",
])
def test_the_repository_writes_database_passwords_as_variables(name):
    assert not _reported((ROOT / name).read_text(encoding="utf-8"))


# Inputs the pattern before #658 read in quadratic time (postgres, "://" and
# "a:" repeated with no "@"), and runs that each part of the new pattern takes, with a few
# characters after them that make several readings.
SUFFIX = " x" + chr(0xE0041) + " y\u200bz w\u2800v"
LONG = {
    "scheme and user repeated": ("postgres" + SEP + "a:") * 20_000,
    "separators only": "://" * 70_000,
    "one long password": "x://a:" + "b" * 200_000,
    "one long run of stars": "x://a:" + "*" * 200_000,
    "one long user": "x://" + "a" * 200_000,
    "users with at signs": "://a@b:" * 30_000,
    "colons and slashes": "x://:/" * 40_000,
    "ports": "x://h:5432/" * 20_000,
    "digits": "x://h:" + "1" * 200_000,
    "placeholders without an at sign": "x://u:${PG}" * 20_000,
    "digests without a credential": ("x" + SEP + "u:p@sha256:") * 20_000,
    "a named scheme with a long user": "postgres" + SEP + "a" * 200_000,
    "a named scheme with a long password over lines": "postgres" + SEP + "a:" + "b\n" * 100_000,
    "named schemes only": ("postgres" + SEP) * 30_000,
    "named schemes as passwords": "mysql" + SEP + "a:" + ("postgres" + SEP) * 20_000,
    "named schemes with short passwords": ("mongodb" + SEP + "a:b ") * 20_000,
}


@pytest.mark.serial
@pytest.mark.timeout(120)
@pytest.mark.parametrize("name", list(LONG))
def test_long_inputs_are_read_in_linear_time(name):
    started = time.perf_counter()
    ConfigGuard().scan_string(LONG[name] + SUFFIX)
    assert time.perf_counter() - started < 10


# The pattern's rules, written out as plain Python: the reference the
# property below compares the pattern with.
_QUOTES = "\"'`"
_NAME_START = string.ascii_letters + "_"
_NAMED_BEFORE = tuple(name + SEP for name in ("postgres", "mysql", "mongodb"))
_DIGEST_LENGTHS = {"sha1:": 40, "sha256:": 64, "sha384:": 96, "sha512:": 128}


def _named_at(text, at):
    """The scheme named before #658 whose "://" starts at *at*, or None."""
    for named in _NAMED_BEFORE:
        if text[at:at + len(named)].lower() == named:
            return named
    return None


def _digest_at(text, at):
    for label, length in _DIGEST_LENGTHS.items():
        value = text[at + len(label):at + len(label) + length]
        end = at + len(label) + length
        if (
            text[at:at + len(label)].isascii()
            and text[at:at + len(label)].lower() == label
            and len(value) == length
            and all(char in string.hexdigits for char in value)
            and (end == len(text) or text[end].isspace() or text[end] in _QUOTES)
        ):
            return True
    return False


def _ends_user(char):
    return char.isspace() or char in _QUOTES + ":/?#[]"


def _in_password(text, at):
    char = text[at]
    if char.isspace() or char in _QUOTES + "@":
        return False
    return char != ":" or text[at + 1:at + 3] != "//"


def _placeholder(password):
    if password.startswith("${") and password.endswith("}"):
        name, rest = password[2:-1], _NAME_START + string.digits
    elif password.startswith("<") and password.endswith(">"):
        name, rest = password[1:-1], _NAME_START + string.digits + "-"
    else:
        return False
    return bool(name) and name[0] in _NAME_START and all(char in rest for char in name)


def _port_first(password):
    digits = len(password) - len(password.lstrip(string.digits))
    return 1 <= digits <= 5 and password[digits:digits + 1] in ("/", "?", "#")


def _credential_end(text, at):
    """Where the credential after the "://" at *at* ends, or None."""
    i = at + 3
    while i < len(text) and not _ends_user(text[i]):
        i += 1
    if text[i:i + 1] != ":":
        return None
    start = j = i + 1
    while j < len(text) and _in_password(text, j):
        j += 1
    password = text[start:j]
    if not password or text[j:j + 1] != "@" or _port_first(password) or _placeholder(password):
        return None
    if _digest_at(text, j + 1):
        return None
    return j + 1


def _end_as_before(text, at):
    """Where the credential of the scheme named before #658 at *at* ends,
    read with that pattern's reach, or None."""
    user = at + len(_named_at(text, at))
    colon = text.find(":", user)
    if colon <= user:
        return None
    j = colon + 1
    while j < len(text) and text[j] != "@" and _named_at(text, j) is None:
        j += 1
    if j == colon + 1 or text[j:j + 1] != "@" or _placeholder(text[colon + 1:j]):
        return None
    return j + 1


def _reference_spans(text):
    """The matches, leftmost first: at each place, the reading of the
    schemes named before #658, then the one-token reading."""
    spans, at = [], 0
    while at < len(text):
        end = _end_as_before(text, at) if _named_at(text, at) else None
        if end is None and text.startswith("://", at):
            end = _credential_end(text, at)
        if end is None:
            at += 1
        else:
            spans.append((at, end))
            at = end
    return spans


PIECES = [
    "://", "postgresql", "+psycopg2", "POSTGRES", "mysql", "mongodb", "redis", "u", "admin", PASSWORD[:6],
    ":", "@", "/", "//", "?", "#", "[", "]", " ", "\t", "\n", "\u00a0", '"', "'", "`",
    "5432", "123456", "${PG}", "${PG:-x}", "$PG", "<pw>", "<>", "***", "*", "{", "}",
    "sha256:" + SHA256, "sha256:", "SHA256", "a" * 64,
    "\u200b", "\u0436", "\u212a", "\uff1a", "\uff20", chr(0x1C), chr(0xE003A),
]


@settings(max_examples=600, deadline=None)
@given(pieces=st.lists(st.sampled_from(PIECES), max_size=14))
def test_the_pattern_finds_what_its_rules_say(pieces):
    text = "".join(pieces)
    expected = _reference_spans(text)
    assert [m.span() for m in COMPILED.finditer(text)] == expected
    compiled = ConfigGuard().compiled_patterns["DATABASE_URL"]
    assert [m.span() for m in compiled.finditer(text)] == expected


OLD = re.compile(OLD_PATTERN, re.IGNORECASE)


def _lost_on_purpose(text, found):
    """Whether a match of the pattern before #658 is a form this PR reads
    out on purpose: a placeholder password, or one that holds the scheme
    and "://" of the next URL of the three schemes."""
    colon = text.index(":", found.end(1) + 3)
    password = text[colon + 1:found.end() - 1]
    return _placeholder(password) or any(_named_at(password, at) for at in range(len(password)))


# Pieces around a URL of the three schemes named before #658, so each text
# holds a match of that pattern.
NAMED_PIECES = [
    "postgres" + SEP, "mysql" + SEP, "MONGODB" + SEP, "mysql+py", "postgresql" + SEP, "redis" + SEP, "://",
    "u", "admin", "ab", ":", "@", "/", "//", "?", "#", " ", "\t", "\n", '"', "'", "`",
    "5432", "${PG}", "<pw>", "***", "*", "sha256:" + SHA256, "​", "：",
]
_NAMED_PARTS = st.lists(st.sampled_from(NAMED_PIECES), max_size=6)


@settings(max_examples=600, deadline=None)
@given(
    before=_NAMED_PARTS,
    scheme=st.sampled_from(["postgres", "mysql", "MONGODB", "mysql+pymysql"]),
    user=_NAMED_PARTS,
    password=st.lists(st.sampled_from(NAMED_PIECES), min_size=1, max_size=6),
    after=_NAMED_PARTS,
)
def test_nothing_reported_before_is_lost_but_on_purpose(before, scheme, user, password, after):
    # Each match of the pattern before #658, not only one of them, overlaps
    # a match of the new pattern. The one-token reading can start such a URL
    # at an earlier "://", as a user may hold "@", but none is left out.
    text = "".join(before) + scheme + SEP + "".join(user) + ":" + "".join(password) + "@" + "".join(after)
    spans = [found.span() for found in COMPILED.finditer(text)]
    for found in OLD.finditer(text):
        if not _lost_on_purpose(text, found):
            assert any(start < found.end() and found.start() < end for start, end in spans)


@settings(max_examples=300, deadline=None)
@given(pieces=st.lists(st.sampled_from(PIECES), max_size=14))
def test_scan_string_counts_the_reading_with_the_most_urls(pieces):
    text = "".join(pieces)
    copies = reading_copies(text)
    decoded = json_readings(text)
    if decoded is not None:
        copies += reading_copies(decoded[0])
    expected = max(len(_reference_spans(copy)) for copy in copies)
    assert _found(text).get("DATABASE_URL", 0) == expected
