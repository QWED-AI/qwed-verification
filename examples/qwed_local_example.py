"""
QWEDLocal Example - Ollama Integration

This example shows how to use QWEDLocal with Ollama (FREE local LLMs).

Prerequisites:
1. Install Ollama: https://ollama.com
2. Pull a model: ollama pull llama3
3. Start Ollama: ollama serve
4. Install QWED: pip install qwed
"""

from qwed_sdk import QWEDLocal

# Colorful output
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    # Fallback if colorama not installed
    class Fore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = BLUE = ""
    class Style:
        BRIGHT = RESET_ALL = ""

def example_ollama():
    """Example: Using Ollama (FREE)"""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 60}")
    print(f"Example 1: Ollama (Local - FREE!)")
    print(f"{'=' * 60}{Style.RESET_ALL}")
    
    # Create client pointing to Ollama
    client = QWEDLocal(
        base_url="http://localhost:11434/v1",  # Ollama endpoint
        model="llama3"                         # or mistral, phi3, etc.
    )
    
    # Verify math
    print(f"\n{Fore.YELLOW}🔢 Verifying: What is 2+2?{Style.RESET_ALL}")
    result = client.verify_math("What is 2+2?")
    
    if result.verified:
        print(f"  {Fore.GREEN}✅ Verified: {result.verified}{Style.RESET_ALL}")
        print(f"  {Fore.BLUE}📊 Value: {result.value}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.RED}❌ NOT Verified{Style.RESET_ALL}")
    
    print(f"  {Fore.MAGENTA}🔍 Evidence: {result.evidence}{Style.RESET_ALL}")
    
    if result.error:
        print(f"  {Fore.RED}❌ Error: {result.error}{Style.RESET_ALL}")


def example_openai():
    """Example: Using OpenAI API"""
    print("\n" + "=" * 60)
    print("Example 2: OpenAI (Cloud)")
    print("=" * 60)
    
    import os
    api_key = os.getenv("OPENAI_API_KEY")
    
    if not api_key:
        print("⚠️  Set OPENAI_API_KEY environment variable to run this example")
        return
    
    # Create client with OpenAI
    client = QWEDLocal(
        provider="openai",
        api_key=api_key,
        model="gpt-4o-mini"  # Cheap model
    )
    
    # Verify math
    print("\n🔢 Verifying: What is the derivative of x^2?")
    result = client.verify_math("What is the derivative of x^2?")
    
    print(f"  ✅ Verified: {result.verified}")
    print(f"  📊 Value: {result.value}")
    
    if result.error:
        print(f"  ❌ Error: {result.error}")


def example_anthropic():
    """Example: Using Anthropic Claude"""
    print("\n" + "=" * 60)
    print("Example 3: Anthropic Claude (Cloud)")
    print("=" * 60)
    
    import os
    api_key = os.getenv("ANTHROPIC_API_KEY")
    
    if not api_key:
        print("⚠️  Set ANTHROPIC_API_KEY environment variable to run this example")
        return
    
    # Create client with Anthropic
    client = QWEDLocal(
        provider="anthropic",
        api_key=api_key,
        model="claude-3-haiku-20240307"  # Budget model
    )
    
    # Verify math
    print("\n🔢 Verifying: What is 5! (factorial)?")
    result = client.verify_math("What is 5! (factorial)?")
    
    print(f"  ✅ Verified: {result.verified}")
    print(f"  📊 Value: {result.value}")
    
    if result.error:
        print(f"  ❌ Error: {result.error}")


if __name__ == "__main__":
    print("\n🚀 QWEDLocal Examples\n")
    print("NOTE: QWEDLocal is privacy-first!")
    print("Your API keys and data NEVER leave your machine.")
    print("QWED servers are NOT involved.\n")
    
    # Try Ollama first (FREE!)
    try:
        example_ollama()
    except Exception as e:
        print(f"\n⚠️  Ollama example failed: {e}")
        print("Make sure Ollama is running: ollama serve")
    
    # Try OpenAI (if key set)
    try:
        example_openai()
    except Exception as e:
        print(f"\n⚠️  OpenAI example failed: {e}")
    
    # Try Anthropic (if key set)
    try:
        example_anthropic()
    except Exception as e:
        print(f"\n⚠️  Anthropic example failed: {e}")
    
    print("\n" + "=" * 60)
    print("✅ Examples complete!")
    print("=" * 60)
