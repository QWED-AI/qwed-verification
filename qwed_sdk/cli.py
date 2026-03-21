# Copyright (c) 2024 QWED Team
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
import os
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import click

# Import after path setup
try:
    from qwed_sdk import QWEDLocal, __version__
    from qwed_sdk.qwed_local import QWED, HAS_COLOR
except ImportError:
    click.echo("Error: QWED SDK not installed. Run: pip install qwed", err=True)
    sys.exit(1)


@click.group()
@click.version_option(__version__, prog_name="qwed")
def cli():
    """
    ðŸ”¬ QWED - Model Agnostic AI Verification
    
    Verify LLM outputs with mathematical precision.
    Works with Ollama, OpenAI, Anthropic, Gemini, and more!
    """
    pass

SEPARATOR = "-" * 41


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


def _load_dotenv_if_available() -> None:
    try:
        from dotenv import load_dotenv
        load_dotenv()
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
            name="Anthropic Claude",
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
            "label": "2+2=5",
            "passed": math_bad.get("status") == "CORRECTION_NEEDED",
            "result": "BLOCKED",
        }
    )

    logic_bad = logic_engine.verify_logic({"x": "Int"}, ["x > 5", "x < 3"])
    tests.append(
        {
            "label": "x>5 AND x<3",
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
    except Exception:
        return False
    return response.status_code == 200


def _ensure_local_server_running(server_url: str, jwt_secret: str) -> tuple[bool, bool]:
    if _check_server_health(server_url):
        return True, False

    from urllib.parse import urlparse
    parsed = urlparse(server_url)
    host = parsed.hostname or "127.0.0.1"
    port = str(parsed.port or 8000)

    env = os.environ.copy()
    src = _src_path()
    current_pythonpath = env.get("PYTHONPATH", "")
    if src not in current_pythonpath.split(os.pathsep):
        env["PYTHONPATH"] = f"{src}{os.pathsep}{current_pythonpath}" if current_pythonpath else src
    env["QWED_JWT_SECRET_KEY"] = jwt_secret

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
        "cwd": str(_project_root()),
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

    subprocess.Popen(command, **popen_kwargs)
    for _ in range(15):
        if _check_server_health(server_url):
            return True, True
        time.sleep(1)
    return False, True


def _bootstrap_api_key(server_url: str, organization_name: str) -> tuple[str, str]:
    import httpx

    base = server_url.rstrip("/")
    org_slug = _sanitize_org_slug(organization_name)
    email = f"{org_slug}-{secrets.token_hex(4)}@qwed.local"
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
        click.echo(f"{QWED.BRAND}{'â”' * 50}{QWED.RESET}")
        click.echo(f"{QWED.BRAND}ðŸ”¬ QWED â€” Secure LLM Configuration{QWED.RESET}")
        click.echo(f"{QWED.BRAND}{'â”' * 50}{QWED.RESET}")
    else:
        click.echo("â”" * 50)
        click.echo("ðŸ”¬ QWED â€” Secure LLM Configuration")
        click.echo("â”" * 50)
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
        click.echo(f"{QWED.ERROR if HAS_COLOR else ''}âŒ Invalid choice{QWED.RESET if HAS_COLOR else ''}", err=True)
        sys.exit(1)

    provider = providers[choice - 1]
    click.echo()
    if HAS_COLOR:
        click.echo(f"{QWED.SUCCESS}âœ“ Selected: {provider.name}{QWED.RESET}")
    else:
        click.echo(f"âœ“ Selected: {provider.name}")

    if provider.install_cmd:
        click.echo(f"\nðŸ“¦ Requires: {provider.install_cmd}")
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
        return click.prompt(f"  ðŸ”‘ {desc}", hide_input=True, default=default)
    elif _is_url_env(name):
        return click.prompt(f"  ðŸŒ {desc}", default=default, show_default=True)
    else:
        return click.prompt(f"  {desc}", default=default, show_default=True)

def _collect_single_credential(env_var, is_local_auth: bool):
    """Prompt user for a single env var until valid. Returns (val, is_key, is_url)."""
    if is_local_auth and not env_var.required and not _is_url_env(env_var.name):
        return env_var.default or "", False, False

    while True:
        val = _prompt_for_env_var(env_var)
        val = val.strip() if val else ""

        if env_var.required and not val:
            click.echo(f"  âŒ {env_var.name} is required. Please provide a valid value.", err=True)
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
        c_msg = f"{QWED.SUCCESS}âœ… {msg}{QWED.RESET}" if HAS_COLOR else f"âœ… {msg}"
        click.echo(c_msg)
    else:
        w_msg = f"{QWED.WARNING}âš ï¸  {msg}{QWED.RESET}" if HAS_COLOR else f"âš ï¸  {msg}"
        p_msg = f"{QWED.INFO}   Proceeding anyway (some providers have non-standard key formats){QWED.RESET}" if HAS_COLOR else "   Proceeding anyway (some providers have non-standard key formats)"
        click.echo(w_msg)
        click.echo(p_msg)

def _test_connection_interactive(provider, collected_key, collected_base_url, test_connection, auth_type_enum):
    if provider.auth_type != auth_type_enum.LOCAL:
        should_test = click.confirm("\nðŸ” Would you like to test the connection?", default=False)
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
        c_msg = f"{QWED.SUCCESS}âœ… {msg}{QWED.RESET}" if HAS_COLOR else f"âœ… {msg}"
        click.echo(c_msg)
    else:
        e_msg = f"{QWED.ERROR}âŒ {msg}{QWED.RESET}" if HAS_COLOR else f"âŒ {msg}"
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
            click.echo(f"\n{QWED.SUCCESS}ðŸ”’ Verified: .gitignore includes .env{QWED.RESET}")
        else:
            click.echo("\nðŸ”’ Verified: .gitignore includes .env")
    else:
        if HAS_COLOR:
            click.echo(f"\n{QWED.WARNING}âš ï¸  .env NOT found in .gitignore!{QWED.RESET}")
        else:
            click.echo("\nâš ï¸  .env NOT found in .gitignore!")
        if click.confirm("   Add .env to .gitignore?", default=True):
            if add_env_to_gitignore():
                click.echo("   âœ… Added .env to .gitignore")
            else:
                click.echo("   âŒ Failed to update .gitignore â€” aborting to protect secrets", err=True)
                sys.exit(1)
        else:
            click.echo("   âš ï¸  Aborting: refusing to write secrets without .gitignore protection", err=True)
            sys.exit(1)
    return True

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
        from qwed_new.config import ensure_jwt_secret
        from qwed_new.providers.credential_store import (
            add_env_to_gitignore,
            verify_gitignore,
            write_env_file,
        )
        from qwed_new.providers.key_validator import test_connection, validate_key_format
        from qwed_new.providers.registry import get_provider
    except ImportError as exc:
        click.echo(f"QWED core not found: {type(exc).__name__}", err=True)
        sys.exit(1)

    provider_map = _build_onboarding_provider_map(get_provider)

    click.echo("[QWED] Initializing verification engines...")
    all_ready, engine_report = _required_engine_report()
    for item in engine_report:
        if item["ready"]:
            click.echo(f"  [ok] {item['name']:<8} {item['detail']}")
        else:
            click.echo(f"  [x]  {item['name']:<8} missing  -> {item['install_hint']}")

    if not all_ready:
        click.echo("\nEngine initialization failed. Install missing dependencies and retry.", err=True)
        sys.exit(1)

    if not skip_tests:
        click.echo("\nRunning verification suite...")
        suite = _run_init_smoke_suite()
        failed = [case for case in suite if not case["passed"]]
        for case in suite:
            marker = "[ok]" if case["passed"] else "[x]"
            click.echo(f"  {marker} {case['label']:<24} -> {case['result']}")
        if failed:
            click.echo("\nBuilt-in verification suite failed. Resolve before onboarding.", err=True)
            sys.exit(1)
        click.echo("\nAll engines verified. QWED is operational.")
    else:
        click.echo("\nSkipping verification suite (--skip-tests).")

    click.echo(f"\n{SEPARATOR}")
    click.echo("Step 1/3: LLM Provider Setup")
    click.echo(SEPARATOR)
    click.echo("QWED uses an LLM for natural language translation.")
    click.echo("The LLM is treated as an untrusted translator.")
    click.echo("All outputs are verified deterministically.\n")

    selected = _normalize_provider_choice(
        provider_choice
        or os.getenv("QWED_PROVIDER")
        or ("nvidia" if non_interactive else "")
    )

    if not selected:
        click.echo("Select provider:")
        click.echo("  1. NVIDIA NIM       (recommended)")
        click.echo("  2. OpenAI")
        click.echo("  3. Anthropic Claude")
        click.echo("  4. Google Gemini")
        click.echo("  5. Custom Provider  (any OpenAI-compatible API)")
        choice = click.prompt("\nProvider", default=1, type=int)
        options = ["nvidia", "openai", "anthropic", "gemini", "custom"]
        if choice < 1 or choice > len(options):
            click.echo("Invalid provider selection.", err=True)
            sys.exit(1)
        selected = options[choice - 1]

    if selected not in provider_map:
        click.echo(f"Unsupported provider '{selected}'.", err=True)
        sys.exit(1)

    profile = provider_map[selected]

    resolved_key = (api_key or os.getenv(profile.key_env) or os.getenv("NVIDIA_API_KEY", "")).strip()
    resolved_base_url = (
        (base_url or os.getenv(profile.base_url_env or "", "")).strip()
        if profile.base_url_env
        else ""
    )
    resolved_model = (model or os.getenv(profile.model_env) or profile.default_model).strip()

    click.echo(f"\n{SEPARATOR}")
    click.echo("Step 2/3: API Key")
    click.echo(SEPARATOR)

    if not resolved_key and not non_interactive:
        resolved_key = click.prompt(f"{profile.name} API key", hide_input=True).strip()
    if profile.base_url_env and not resolved_base_url:
        if non_interactive:
            resolved_base_url = profile.default_base_url or ""
        else:
            resolved_base_url = click.prompt(
                f"{profile.name} base URL",
                default=profile.default_base_url or "",
                show_default=True,
            ).strip()
    if not resolved_model and not non_interactive:
        resolved_model = click.prompt(
            f"{profile.name} default model",
            default=profile.default_model,
            show_default=True,
        ).strip()

    if not resolved_key:
        click.echo(f"{profile.key_env} is required for provider '{profile.slug}'.", err=True)
        sys.exit(1)
    if profile.base_url_env and not resolved_base_url:
        click.echo(f"{profile.base_url_env} is required for provider '{profile.slug}'.", err=True)
        sys.exit(1)

    if profile.key_pattern:
        is_valid, message = validate_key_format(resolved_key, profile.key_pattern)
        if not is_valid and non_interactive:
            click.echo(f"Key validation failed: {message}", err=True)
            sys.exit(1)
        if not is_valid:
            click.echo(f"Warning: {message}")

    while True:
        click.echo("\n  Testing connection...")
        if profile.connection_slug == "gemini":
            success, message = _test_gemini_connection(resolved_key)
        else:
            success, message = test_connection(
                provider_slug=profile.connection_slug or "",
                api_key=resolved_key,
                base_url=resolved_base_url or None,
                model=resolved_model,
            )
        if success:
            click.echo("  [ok] Provider connected")
            click.echo("  [ok] Model responding")
            break

        click.echo(f"  [x] {message}", err=True)
        if non_interactive:
            sys.exit(1)

        if not click.confirm("  Retry with updated credentials?", default=True):
            sys.exit(1)
        resolved_key = click.prompt(f"{profile.name} API key", hide_input=True).strip()
        if profile.base_url_env:
            resolved_base_url = click.prompt(
                f"{profile.name} base URL",
                default=resolved_base_url or profile.default_base_url or "",
                show_default=True,
            ).strip()
        resolved_model = click.prompt(
            f"{profile.name} default model",
            default=resolved_model or profile.default_model,
            show_default=True,
        ).strip()

    env_vars = {profile.key_env: resolved_key, profile.model_env: resolved_model}
    if profile.base_url_env:
        env_vars[profile.base_url_env] = resolved_base_url

    try:
        jwt_secret = ensure_jwt_secret()
    except Exception as exc:
        click.echo(f"Failed to prepare JWT secret: {type(exc).__name__}", err=True)
        sys.exit(1)

    env_vars["QWED_JWT_SECRET_KEY"] = jwt_secret

    try:
        _ensure_gitignore_protection_noninteractive(verify_gitignore, add_env_to_gitignore)
        env_path = write_env_file(env_vars, active_provider=profile.active_provider)
    except Exception as exc:
        click.echo(f"Failed to store credentials securely: {type(exc).__name__}", err=True)
        sys.exit(1)

    os.environ.update(env_vars)
    os.environ["ACTIVE_PROVIDER"] = profile.active_provider
    click.echo("  [ok] Credentials stored (.env, mode 0600)")

    click.echo(f"\n{SEPARATOR}")
    click.echo("Step 3/3: Generate QWED API Key")
    click.echo(SEPARATOR)

    if not organization_name:
        organization_name = os.getenv("QWED_ORGANIZATION_NAME", "").strip()
    if not organization_name and non_interactive:
        organization_name = f"qwed-{secrets.token_hex(2)}"
    if not organization_name:
        organization_name = click.prompt("Organization name").strip()
    if not organization_name:
        click.echo("Organization name is required.", err=True)
        sys.exit(1)

    click.echo("\n  Starting local server...")
    server_ready, started_new = _ensure_local_server_running(server_url, jwt_secret)
    if not server_ready:
        click.echo("  [x] Failed to start local server.", err=True)
        click.echo("    Ensure dependencies are installed and `src/` is available in PYTHONPATH.", err=True)
        click.echo(f"    Suggested fix: pip install -e \"{_project_root()}\"", err=True)
        sys.exit(1)
    click.echo("  [ok] Local server initialized")
    if started_new:
        click.echo("  [ok] Runtime path guard applied (src/ added to PYTHONPATH)")

    try:
        qwed_api_key, actual_org_name = _bootstrap_api_key(server_url, organization_name)
    except Exception as exc:
        click.echo(f"  [x] API key bootstrap failed: {exc}", err=True)
        sys.exit(1)

    click.echo("  [ok] Organization created")
    if actual_org_name != organization_name:
        click.echo(f"  [ok] Organization alias used: {actual_org_name}")

    click.echo(f"\n  Your API key: {qwed_api_key}")
    click.echo("  Warning: Save this key. It is shown only once.")

    click.echo(f"\n{SEPARATOR}")
    click.echo("QWED is ready.")
    verify_url = f"{server_url.rstrip('/')}/verify/math"
    click.echo("\nVerify an output:")
    click.echo(f"  curl -X POST {verify_url} \\")
    click.echo(f"    -H \"x-api-key: {qwed_api_key}\" \\")
    click.echo("    -H \"Content-Type: application/json\" \\")
    click.echo("    -d '{\"expression\": \"2+2=4\"}'")
    click.echo("\nDocumentation: https://docs.qwedai.com")
    click.echo(SEPARATOR)
    click.echo(f"\nEnvironment file: {env_path}")


@cli.command()
@click.argument('query')
@click.option('--provider', '-p', default=None, help='LLM provider (openai/anthropic/gemini)')
@click.option('--model', '-m', default=None, help='Model name (e.g., gpt-4o-mini, llama3)')
@click.option('--base-url', default=None, help='Custom API endpoint (e.g., http://localhost:11434/v1)')
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
        qwed verify "5!" --base-url http://localhost:11434/v1 --model llama3
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
        import logging
        logging.getLogger(__name__).debug("python-dotenv not installed, skipping auto-load")
        if not quiet:
            err_msg = f"{QWED.ERROR}âš ï¸  python-dotenv not installed. Run 'pip install python-dotenv' for auto-loading .env{QWED.RESET}" if HAS_COLOR else "âš ï¸  python-dotenv not installed. Run 'pip install python-dotenv' for auto-loading .env"
            click.echo(err_msg, err=True)
    
    try:
        # Auto-detect provider/base_url from ACTIVE_PROVIDER
        if not provider and not base_url:
            import os as _os
            active = _os.getenv("ACTIVE_PROVIDER", "").strip()
            if active == "ollama" or not active:
                # Use Ollama (LOCAL): respect user-configured env vars
                base_url = _os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
                model = model or _os.getenv("OLLAMA_MODEL", "llama3")
                if HAS_COLOR and not quiet:
                    click.echo(f"{QWED.INFO}\u2139\ufe0f  Using Ollama at {base_url}{QWED.RESET}")
            elif active == "openai-compatible" or active == "openai_compat":
                base_url = _os.getenv("CUSTOM_BASE_URL", "")
                if not base_url:
                    err_msg = f"{QWED.ERROR}âŒ CUSTOM_BASE_URL is required for openai-compatible provider{QWED.RESET}" if HAS_COLOR else "âŒ CUSTOM_BASE_URL is required for openai-compatible provider"
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
                }
                if not api_key:
                    env_key = provider_key_env.get(provider, "QWED_API_KEY")
                    api_key = _os.getenv(env_key, _os.getenv("QWED_API_KEY", ""))
                if HAS_COLOR and not quiet:
                    click.echo(f"{QWED.INFO}â„¹ï¸  Using configured provider: {active}{QWED.RESET}")
        
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
                click.echo(f"{QWED.ERROR}âŒ API key required for {provider}{QWED.RESET}", err=True)
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
                click.echo(f"âœ… VERIFIED: {result.value}")
            else:
                click.echo(f"âŒ {result.error or 'Verification failed'}", err=True)
        
        if not result.verified:
            sys.exit(1)
    
    except Exception as e:
        click.echo(f"{QWED.ERROR if HAS_COLOR else ''}âŒ Error: {str(e)}{QWED.RESET if HAS_COLOR else ''}", err=True)
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
        click.echo(f"{QWED.SUCCESS if HAS_COLOR else ''}âœ… Cache cleared!{QWED.RESET if HAS_COLOR else ''}")
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
        âœ… VERIFIED â†’ 4
        > derivative of x^2
        âœ… VERIFIED â†’ 2*x
    """
    if HAS_COLOR:
        click.echo(f"\n{QWED.BRAND}ðŸ”¬ QWED Interactive Mode{QWED.RESET}")
        click.echo(f"{QWED.INFO}Type 'exit' or 'quit' to quit{QWED.RESET}\n")
    else:
        click.echo("\nðŸ”¬ QWED Interactive Mode")
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
                base_url="http://localhost:11434/v1",
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
                    click.echo(f"âœ… {result.value}")
                else:
                    click.echo(f"âŒ {result.error or 'Failed'}")
            
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
        click.echo(f"{QWED.ERROR if HAS_COLOR else ''}âŒ PII features not installed{QWED.RESET if HAS_COLOR else ''}", err=True)
        click.echo("\nðŸ“¦ Install with:", err=True)
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
        click.echo(f"{QWED.ERROR if HAS_COLOR else ''}âŒ Core config manager not found{QWED.RESET if HAS_COLOR else ''}", err=True)
        sys.exit(1)
        
    try:
        if HAS_COLOR:
            click.echo(f"{QWED.INFO}\u2139\ufe0f  Downloading provider from {url}...{QWED.RESET}")
        else:
            click.echo(f"\u2139\ufe0f  Downloading provider from {url}...")
            
        manager = ProviderConfigManager()
        slug = manager.import_provider_from_url(url)
        
        if HAS_COLOR:
            click.echo(f"{QWED.SUCCESS}âœ… Successfully imported provider '{slug}'!{QWED.RESET}")
            click.echo(f"{QWED.INFO}   You can now run 'qwed init' and select it from the interactive menu.{QWED.RESET}")
        else:
            click.echo(f"âœ… Successfully imported provider '{slug}'!")
            click.echo("   You can now run 'qwed init' and select it from the interactive menu.")
    except Exception as e:
        if HAS_COLOR:
            click.echo(f"{QWED.ERROR}âŒ Failed to import provider: {str(e)}{QWED.RESET}", err=True)
        else:
            click.echo(f"âŒ Failed to import provider: {str(e)}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()
