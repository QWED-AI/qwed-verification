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

import click
import sys
from typing import Optional

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
    🔬 QWED - Model Agnostic AI Verification
    
    Verify LLM outputs with mathematical precision.
    Works with Ollama, OpenAI, Anthropic, Gemini, and more!
    """
    pass


from typing import Any

def _print_init_header():
    """Print branded init wizard header."""
    click.echo()
    if HAS_COLOR:
        click.echo(f"{QWED.BRAND}{'━' * 50}{QWED.RESET}")
        click.echo(f"{QWED.BRAND}🔬 QWED — Secure LLM Configuration{QWED.RESET}")
        click.echo(f"{QWED.BRAND}{'━' * 50}{QWED.RESET}")
    else:
        click.echo("━" * 50)
        click.echo("🔬 QWED — Secure LLM Configuration")
        click.echo("━" * 50)
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
        click.echo(f"{QWED.ERROR if HAS_COLOR else ''}❌ Invalid choice{QWED.RESET if HAS_COLOR else ''}", err=True)
        sys.exit(1)

    provider = providers[choice - 1]
    click.echo()
    if HAS_COLOR:
        click.echo(f"{QWED.SUCCESS}✓ Selected: {provider.name}{QWED.RESET}")
    else:
        click.echo(f"✓ Selected: {provider.name}")

    if provider.install_cmd:
        click.echo(f"\n📦 Requires: {provider.install_cmd}")
    return provider

def _collect_credentials(provider, auth_type_enum) -> tuple:
    """Collect env vars, key, and base_url from user input."""
    env_vars = {}
    collected_key = None
    collected_base_url = None

    for env_var in provider.env_vars:
        if provider.auth_type == auth_type_enum.LOCAL and not env_var.required and "URL" not in env_var.name and "ENDPOINT" not in env_var.name:
            env_vars[env_var.name] = env_var.default or ""
            continue

        while True:
            if "KEY" in env_var.name or "key" in env_var.name.lower() or "API" in env_var.name:
                click.echo()
                val = click.prompt(
                    f"  🔑 {env_var.description}",
                    hide_input=True,
                    default=env_var.default or "",
                )
            elif "URL" in env_var.name or "ENDPOINT" in env_var.name:
                val = click.prompt(
                    f"  🌐 {env_var.description}",
                    default=env_var.default or "",
                    show_default=True,
                )
            else:
                val = click.prompt(
                    f"  {env_var.description}",
                    default=env_var.default or "",
                    show_default=True,
                )

            val = val.strip() if val else ""

            if env_var.required and not val:
                click.echo(f"  ❌ {env_var.name} is required. Please provide a valid value.", err=True)
                continue

            env_vars[env_var.name] = val
            if ("KEY" in env_var.name or "key" in env_var.name.lower() or "API" in env_var.name) and val:
                collected_key = val
            elif ("URL" in env_var.name or "ENDPOINT" in env_var.name) and val:
                collected_base_url = val
            break

    return env_vars, collected_key, collected_base_url

def _validate_key(provider, collected_key, validate_key_format):
    if not (collected_key and provider.key_pattern):
        return
    is_valid, msg = validate_key_format(collected_key, provider.key_pattern)
    click.echo()
    if is_valid:
        c_msg = f"{QWED.SUCCESS}✅ {msg}{QWED.RESET}" if HAS_COLOR else f"✅ {msg}"
        click.echo(c_msg)
    else:
        w_msg = f"{QWED.WARNING}⚠️  {msg}{QWED.RESET}" if HAS_COLOR else f"⚠️  {msg}"
        p_msg = f"{QWED.INFO}   Proceeding anyway (some providers have non-standard key formats){QWED.RESET}" if HAS_COLOR else "   Proceeding anyway (some providers have non-standard key formats)"
        click.echo(w_msg)
        click.echo(p_msg)

def _test_connection_interactive(provider, collected_key, collected_base_url, test_connection, auth_type_enum):
    if provider.auth_type != auth_type_enum.LOCAL:
        should_test = click.confirm("\n🔍 Would you like to test the connection?", default=False)
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
        c_msg = f"{QWED.SUCCESS}✅ {msg}{QWED.RESET}" if HAS_COLOR else f"✅ {msg}"
        click.echo(c_msg)
    else:
        e_msg = f"{QWED.ERROR}❌ {msg}{QWED.RESET}" if HAS_COLOR else f"❌ {msg}"
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
            click.echo(f"\n{QWED.SUCCESS}🔒 Verified: .gitignore includes .env{QWED.RESET}")
        else:
            click.echo("\n🔒 Verified: .gitignore includes .env")
    else:
        if HAS_COLOR:
            click.echo(f"\n{QWED.WARNING}⚠️  .env NOT found in .gitignore!{QWED.RESET}")
        else:
            click.echo("\n⚠️  .env NOT found in .gitignore!")
        if click.confirm("   Add .env to .gitignore?", default=True):
            if add_env_to_gitignore():
                click.echo("   ✅ Added .env to .gitignore")
            else:
                click.echo("   ❌ Failed to update .gitignore — aborting to protect secrets", err=True)
                sys.exit(1)
        else:
            click.echo("   ⚠️  Aborting: refusing to write secrets without .gitignore protection", err=True)
            sys.exit(1)
    return True

@cli.command()
def init():
    """
    🔒 Configure your LLM provider securely.

    Interactive wizard to set up API keys and provider configuration.
    Writes credentials to .env with restrictive permissions.

    Example:
        qwed init
    """
    try:
        from qwed_new.providers.registry import list_providers, get_provider, AuthType
        from qwed_new.providers.key_validator import validate_key_format, mask_key, test_connection
        from qwed_new.providers.credential_store import write_env_file, verify_gitignore, add_env_to_gitignore
    except ImportError:
        click.echo(f"{QWED.ERROR if HAS_COLOR else ''}❌ QWED core not found. Make sure qwed is installed.{QWED.RESET if HAS_COLOR else ''}", err=True)
        sys.exit(1)

    _print_init_header()
    provider = _select_provider(list_providers())
    env_vars, collected_key, collected_base_url = _collect_credentials(provider, AuthType)
    _validate_and_test_connection(provider, collected_key, collected_base_url, validate_key_format, test_connection, AuthType)

    set_default = click.confirm(
        f"\n⚙️  Set {provider.name} as default active provider?",
        default=True,
    )
    active_slug = None
    if set_default:
        # Note: "openai_compat" used in env vars for shell compatibility
        # (hyphens can cause issues in some shells when sourcing .env)
        slug_map = {
            "openai": "openai",
            "anthropic": "anthropic",
            "ollama": "ollama",
            "openai-compatible": "openai_compat",
        }
        active_slug = slug_map.get(provider.slug, provider.slug)

    _ensure_gitignore_protection(verify_gitignore, add_env_to_gitignore)

    click.echo()
    env_path = write_env_file(env_vars, active_provider=active_slug)
    if HAS_COLOR:
        click.echo(f"{QWED.SUCCESS}📁 Written to {env_path}{QWED.RESET}")
    else:
        click.echo(f"📁 Written to {env_path}")

    click.echo()
    if HAS_COLOR:
        click.echo(f"{QWED.BRAND}{'━' * 50}{QWED.RESET}")
        click.echo(f"{QWED.SUCCESS}🚀 Ready! Try: qwed verify \"What is 2+2?\"{QWED.RESET}")
        click.echo(f"{QWED.BRAND}{'━' * 50}{QWED.RESET}")
    else:
        click.echo("━" * 50)
        click.echo("🚀 Ready! Try: qwed verify \"What is 2+2?\"")
        click.echo("━" * 50)
    click.echo()


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
            err_msg = f"{QWED.ERROR}⚠️  python-dotenv not installed. Run 'pip install python-dotenv' for auto-loading .env{QWED.RESET}" if HAS_COLOR else "⚠️  python-dotenv not installed. Run 'pip install python-dotenv' for auto-loading .env"
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
                    err_msg = f"{QWED.ERROR}❌ CUSTOM_BASE_URL is required for openai-compatible provider{QWED.RESET}" if HAS_COLOR else "❌ CUSTOM_BASE_URL is required for openai-compatible provider"
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
                    click.echo(f"{QWED.INFO}ℹ️  Using configured provider: {active}{QWED.RESET}")
        
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
                click.echo(f"{QWED.ERROR}❌ API key required for {provider}{QWED.RESET}", err=True)
                click.echo(f"Set QWED_API_KEY env var or use --api-key", err=True)
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
                click.echo(f"✅ VERIFIED: {result.value}")
            else:
                click.echo(f"❌ {result.error or 'Verification failed'}", err=True)
        
        if not result.verified:
            sys.exit(1)
    
    except Exception as e:
        click.echo(f"{QWED.ERROR if HAS_COLOR else ''}❌ Error: {str(e)}{QWED.RESET if HAS_COLOR else ''}", err=True)
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
        click.echo(f"{QWED.SUCCESS if HAS_COLOR else ''}✅ Cache cleared!{QWED.RESET if HAS_COLOR else ''}")
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
        ✅ VERIFIED → 4
        > derivative of x^2
        ✅ VERIFIED → 2*x
    """
    if HAS_COLOR:
        click.echo(f"\n{QWED.BRAND}🔬 QWED Interactive Mode{QWED.RESET}")
        click.echo(f"{QWED.INFO}Type 'exit' or 'quit' to quit{QWED.RESET}\n")
    else:
        click.echo("\n🔬 QWED Interactive Mode")
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
                    click.echo(f"✅ {result.value}")
                else:
                    click.echo(f"❌ {result.error or 'Failed'}")
            
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
        click.echo(f"{QWED.ERROR if HAS_COLOR else ''}❌ PII features not installed{QWED.RESET if HAS_COLOR else ''}", err=True)
        click.echo("\n📦 Install with:", err=True)
        click.echo("   pip install 'qwed[pii]'", err=True)
        click.echo("   python -m spacy download en_core_web_lg", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()
