"""
Configuration Management for QWED.

This module handles environment variables and provider selection.
"""

import os
from dotenv import load_dotenv
from enum import Enum

load_dotenv()

class ProviderType(str, Enum):
    OPENAI = "openai"
    AZURE_OPENAI = "azure_openai"
    ANTHROPIC = "anthropic"
    CLAUDE_OPUS = "claude_opus"
    GEMINI = "gemini"
    AUTO = "auto"

class Settings:
    # Database Config
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./qwed.db")

    # Redis Config
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Security
    API_KEY_SECRET = os.getenv("API_KEY_SECRET", "change-me-in-production")

    # Default to Azure OpenAI if not specified
    ACTIVE_PROVIDER = os.getenv("ACTIVE_PROVIDER", ProviderType.AZURE_OPENAI)
    
    # OpenAI Config (Direct API)
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4")
    
    # Azure OpenAI Config
    AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
    AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
    AZURE_OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT")
    AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION")
    
    # Anthropic Config (Claude 3.5 Sonnet)
    ANTHROPIC_ENDPOINT = os.getenv("ANTHROPIC_ENDPOINT")
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
    ANTHROPIC_DEPLOYMENT = os.getenv("ANTHROPIC_DEPLOYMENT")
    ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
    
    # Claude Opus 4.5 Config
    CLAUDE_OPUS_ENDPOINT = os.getenv("CLAUDE_OPUS_ENDPOINT")
    CLAUDE_OPUS_API_KEY = os.getenv("CLAUDE_OPUS_API_KEY")
    CLAUDE_OPUS_DEPLOYMENT = os.getenv("CLAUDE_OPUS_DEPLOYMENT", "claude-opus-4-5")
    
    # Google Gemini Config
    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-pro")

settings = Settings()
