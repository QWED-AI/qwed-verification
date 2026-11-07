"""#591: the server read some settings before it loaded .env.

``uvicorn qwed_new.api.main:app`` imported the math worker, the database, the
rate limiter and the auth module before anything imported ``qwed_new.config``,
which loads ``.env``. A value written only in ``.env`` was ignored by them:
the math worker ran on its defaults, the database fell back to
``sqlite:///./qwed.db``, the server refused to start without
``QWED_JWT_SECRET_KEY`` although ``.env`` set it, and a math setting the
worker cannot use did not stop the start but made every maths job BLOCKED.
``api/main.py`` now imports ``qwed_new.config`` before any other QWED module.

Each case imports the server in a fresh interpreter, as uvicorn does, from a
directory whose ``.env`` holds the settings, with none of them in the process
environment.
"""

import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import qwed_new

SRC = str(Path(qwed_new.__file__).resolve().parents[1])

# Settings the child never inherits from the environment the tests run in.
# A setting a case writes to .env is removed from the child's environment
# as well, so the child can read it only from .env.
_NOT_INHERITED = (
    "DATABASE_URL",
    "QWED_RATE_LIMIT_PER_KEY",
    "QWED_MATH_WORKERS",
    "QWED_MATH_TIMEOUT_SECONDS",
    "QWED_MATH_MAX_WAITING",
    "QWED_MATH_WORKER_MEMORY_MB",
    "QWED_BATCH_MATH_BUDGET_SECONDS",
    "PYTHON_DOTENV_DISABLED",
)

_IMPORT_THE_SERVER = """
import json
import qwed_new.api.main
from qwed_new.core import database, math_worker, rate_limiter
print(json.dumps({
    "workers": math_worker.WORKERS,
    "timeout": math_worker.TIMEOUT_SECONDS,
    "database_url": database.DATABASE_URL,
    "per_key_limit": rate_limiter.rate_limiter.PER_KEY_LIMIT,
}))
"""


def _import_the_server(tmp_path, dotenv):
    """Import the server in a fresh interpreter whose working directory has
    *dotenv* as its .env, and whose environment holds none of its keys. The
    home directory is empty, so ~/.qwed/.env is not read."""
    (tmp_path / ".env").write_text("".join(f"{k}={v}\n" for k, v in dotenv.items()), encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if k not in _NOT_INHERITED and k not in dotenv}
    env["HOME"] = env["USERPROFILE"] = str(home)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [SRC, env.get("PYTHONPATH")]))
    return subprocess.run(
        [sys.executable, "-c", _IMPORT_THE_SERVER],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def _settings(run):
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout.strip().splitlines()[-1])


def test_the_server_starts_with_its_secrets_only_in_dotenv(tmp_path):
    dotenv = {
        "API_KEY_SECRET": secrets.token_urlsafe(32),
        "QWED_JWT_SECRET_KEY": secrets.token_urlsafe(32),
        "QWED_API_KEY_LOOKUP_SECRET": secrets.token_urlsafe(32),
        "QWED_AUDIT_SECRET_KEY": secrets.token_urlsafe(32),
        "QWED_CORS_ORIGINS": "http://localhost:3000",
    }

    _settings(_import_the_server(tmp_path, dotenv))


def test_the_math_database_and_rate_limit_settings_are_read_from_dotenv(tmp_path):
    # The secrets come from the environment here, so the import starts
    # either way and only where each setting was read from is checked.
    database_url = f"sqlite:///{(tmp_path / 'from_dotenv.db').as_posix()}"
    dotenv = {
        "QWED_MATH_WORKERS": "5",
        "QWED_MATH_TIMEOUT_SECONDS": "7.5",
        "DATABASE_URL": database_url,
        "QWED_RATE_LIMIT_PER_KEY": "7",
    }

    settings = _settings(_import_the_server(tmp_path, dotenv))

    assert settings == {"workers": 5, "timeout": 7.5, "database_url": database_url, "per_key_limit": 7}


def test_a_math_setting_in_dotenv_the_worker_cannot_use_stops_the_server(tmp_path):
    # The secrets come from the environment here, so only the math setting
    # can stop the import. Before #591 the import went on, and each worker
    # raised as it started, so every maths job was BLOCKED.
    run = _import_the_server(tmp_path, {"QWED_MATH_TIMEOUT_SECONDS": "inf"})

    assert run.returncode != 0
    assert "MathSettingError: QWED_MATH_TIMEOUT_SECONDS must be a number" in run.stderr
