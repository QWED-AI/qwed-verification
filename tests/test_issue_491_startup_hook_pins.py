"""#491: a startup hook can be allowed by the digest of its exact contents.

setuptools' ``distutils-precedence.pth`` (in every new Python 3.11 venv)
uses ``__import__(``, and coverage's ``a1_coverage.pth`` uses ``exec(``.
An allowlisted name is still scanned for those patterns, so allowing these
files by name did not help, and the only way to start the server was
``QWED_SKIP_ENV_INTEGRITY_CHECK=true``. An allowlist entry can now be
``NAME.pth:sha256:<hex>``: the file is allowed while its contents hash to
that digest, and any change to it fails the check.
"""

import hashlib
import os
from unittest.mock import patch

import pytest

from qwed_new.api import main as api_main
from qwed_sdk.guards import environment_guard
from qwed_sdk.guards.environment_guard import (
    StartupHookGuard,
    parse_startup_hook_allowlist,
)

# The two hooks quoted in #491 (setuptools 65.5.0 and coverage 7.13.1).
SETUPTOOLS_HOOK = (
    "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; "
    "enabled and __import__('_distutils_hack').add_shim(); \n"
)
COVERAGE_HOOK = (
    "import sys; exec('import os\\n\\nif os.getenv(\"COVERAGE_PROCESS_START\") or "
    "os.getenv(\"COVERAGE_PROCESS_CONFIG\"):\\n try:\\n  import coverage\\n except:\\n  pass\\n "
    "else:\\n  coverage.process_startup(slug=\"pth\")')\n"
)
SETUPTOOLS = "distutils-precedence.pth"
COVERAGE = "a1_coverage.pth"


def _write(directory, name, content):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(content)
    return path


def _digest(content):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _check(directory, **kwargs):
    guard = StartupHookGuard(**kwargs)
    with patch.object(guard, "_get_site_dirs", return_value=[str(directory)]):
        return guard.verify_environment_integrity()


@pytest.fixture
def venv(tmp_path):
    """A site-packages directory holding the two standard hooks."""
    _write(tmp_path, SETUPTOOLS, SETUPTOOLS_HOOK)
    _write(tmp_path, COVERAGE, COVERAGE_HOOK)
    return tmp_path


# ------------------------------------------------------------------ parsing

def test_names_and_pins_are_parsed_apart():
    digest = "A" * 64

    names, pins = parse_startup_hook_allowlist(f" my_hook.pth , {SETUPTOOLS}:sha256:{digest},, ")

    assert names == {"my_hook.pth"}
    assert pins == {SETUPTOOLS: "a" * 64}


@pytest.mark.parametrize("entry", [
    f"{SETUPTOOLS}:sha256:{'a' * 63}",       # digest too short
    f"{SETUPTOOLS}:sha256:{'g' * 64}",       # not hex
    f"{SETUPTOOLS}:md5:{'a' * 32}",          # another algorithm
    f"{SETUPTOOLS}:{'a' * 64}",              # no algorithm
    f"hook.txt:sha256:{'a' * 64}",           # not a .pth name
    f"site/{SETUPTOOLS}:sha256:{'a' * 64}",  # a directory: pins match base names
    f"site\\{SETUPTOOLS}:sha256:{'a' * 64}",
])
def test_a_malformed_pin_raises_instead_of_becoming_a_name(entry):
    with pytest.raises(ValueError, match="NAME.pth:sha256"):
        parse_startup_hook_allowlist(entry)


# -------------------------------------------------------------------- guard

def test_by_name_the_standard_hooks_still_fail(venv):
    result = _check(venv, allowed_pth_files={COVERAGE})

    assert result["verified"] is False
    assert result["counts"]["malicious"] == 2


def test_pinned_standard_hooks_pass(venv):
    pins = {SETUPTOOLS: _digest(SETUPTOOLS_HOOK), COVERAGE: _digest(COVERAGE_HOOK)}

    result = _check(venv, pinned_pth_digests=pins)

    assert result["verified"] is True
    assert result["content_findings"] == []


def test_a_changed_pinned_hook_fails(venv):
    pins = {SETUPTOOLS: _digest(SETUPTOOLS_HOOK), COVERAGE: _digest(COVERAGE_HOOK)}
    tampered = _write(venv, SETUPTOOLS, SETUPTOOLS_HOOK + "import evil_payload\n")

    result = _check(venv, pinned_pth_digests=pins)

    assert result["verified"] is False
    assert result["suspicious_hooks"] == [tampered]
    assert result["counts"]["digest_mismatch"] == 1
    assert "1 not matching its pinned digest" in result["message"]
    (finding,) = result["content_findings"]
    assert finding.startswith(f"Digest mismatch: {tampered}")


def test_a_pin_overrides_an_allowlisted_name(tmp_path):
    # pip.pth is allowlisted by default and clean, but its pin is for other contents.
    _write(tmp_path, "pip.pth", "# pip\n")

    result = _check(tmp_path, pinned_pth_digests={"pip.pth": _digest("# other\n")})

    assert result["verified"] is False
    assert result["counts"]["digest_mismatch"] == 1


def test_an_unreadable_pinned_hook_fails(venv, monkeypatch):
    def _unreadable(_path):
        raise PermissionError("denied")

    monkeypatch.setattr(environment_guard, "_sha256_of", _unreadable)
    pins = {SETUPTOOLS: _digest(SETUPTOOLS_HOOK), COVERAGE: _digest(COVERAGE_HOOK)}

    result = _check(venv, pinned_pth_digests=pins)

    assert result["verified"] is False
    assert result["counts"]["unreadable"] == 2


def test_other_hooks_are_checked_as_before_next_to_a_pin(venv):
    _write(venv, "litellm_init.pth", "import os; exec(base64.b64decode('...'))")
    pins = {SETUPTOOLS: _digest(SETUPTOOLS_HOOK), COVERAGE: _digest(COVERAGE_HOOK)}

    result = _check(venv, pinned_pth_digests=pins)

    assert result["verified"] is False
    assert result["counts"]["malicious"] == 1
    assert result["counts"]["digest_mismatch"] == 0


# ------------------------------------------------------------ server startup

def test_startup_passes_the_environment_pins_to_the_guard(venv, monkeypatch):
    monkeypatch.delenv("QWED_SKIP_ENV_INTEGRITY_CHECK", raising=False)
    monkeypatch.setenv(
        "QWED_ALLOWED_STARTUP_PTH_FILES",
        f"{SETUPTOOLS}:sha256:{_digest(SETUPTOOLS_HOOK)},{COVERAGE}:sha256:{_digest(COVERAGE_HOOK)}",
    )

    with patch.object(StartupHookGuard, "_get_site_dirs", return_value=[str(venv)]):
        api_main._enforce_environment_integrity()  # does not raise


def test_startup_still_fails_on_the_hooks_without_pins(venv, monkeypatch):
    monkeypatch.delenv("QWED_SKIP_ENV_INTEGRITY_CHECK", raising=False)
    monkeypatch.setenv("QWED_ALLOWED_STARTUP_PTH_FILES", f"{SETUPTOOLS},{COVERAGE}")

    with (
        patch.object(StartupHookGuard, "_get_site_dirs", return_value=[str(venv)]),
        pytest.raises(RuntimeError, match="COMPROMISED_ENVIRONMENT_STARTUP_HOOK"),
    ):
        api_main._enforce_environment_integrity()


def test_startup_refuses_a_malformed_pin(monkeypatch):
    monkeypatch.delenv("QWED_SKIP_ENV_INTEGRITY_CHECK", raising=False)
    monkeypatch.setenv("QWED_ALLOWED_STARTUP_PTH_FILES", f"{SETUPTOOLS}:sha256:abc")

    with pytest.raises(ValueError, match="NAME.pth:sha256"):
        api_main._enforce_environment_integrity()
