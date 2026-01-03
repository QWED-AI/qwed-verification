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


@cli.command()
@click.argument('query')
@click.option('--provider', '-p', default=None, help='LLM provider (openai/anthropic/gemini)')
@click.option('--model', '-m', default=None, help='Model name (e.g., gpt-4o-mini, llama3)')
@click.option('--base-url', default=None, help='Custom API endpoint (e.g., http://localhost:11434/v1)')
@click.option('--api-key', default=None, envvar='QWED_API_KEY', help='API key (or set QWED_API_KEY env var)')
@click.option('--no-cache', is_flag=True, help='Disable caching')
@click.option('--quiet', '-q', is_flag=True, help='Minimal output')
def verify(query: str, provider: Optional[str], model: Optional[str], 
           base_url: Optional[str], api_key: Optional[str], 
           no_cache: bool, quiet: bool):
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
    
    try:
        # Auto-detect provider/base_url
        if not provider and not base_url:
            # Try Ollama first (FREE!)
            base_url = "http://localhost:11434/v1"
            model = model or "llama3"
            
            if HAS_COLOR and not quiet:
                click.echo(f"{QWED.INFO}ℹ️  No provider specified, trying Ollama...{QWED.RESET}")
        
        # Create client
        if base_url:
            client = QWEDLocal(
                base_url=base_url,
                model=model or "llama3",
                cache=not no_cache
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
                cache=not no_cache
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


if __name__ == '__main__':
    cli()
