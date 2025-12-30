import os
import requests
from typing import Optional, Dict, Any, Union, List
from .models import VerificationResponse, LogicResponse, FactResponse

class QwedClient:
    """
    Client for the QWED Verification API.
    """
    
    def __init__(self, api_key: str, base_url: str = "https://api.qwed.tech/v1"):
        """
        Initialize the QWED client.
        
        Args:
            api_key: Your QWED API key.
            base_url: The base URL of the QWED API. Defaults to production.
                      Use "http://localhost:8000" for local development.
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        })

    def verify_natural_language(self, query: str, provider: Optional[str] = None) -> VerificationResponse:
        """
        Verify a natural language math or general query.
        
        Args:
            query: The question to verify (e.g., "What is 10 + 10?").
            provider: Optional LLM provider to use ("azure_openai", "anthropic").
            
        Returns:
            VerificationResponse object containing the result.
        """
        payload = {"query": query}
        if provider:
            payload["provider"] = provider
            
        response = self.session.post(f"{self.base_url}/verify/natural_language", json=payload)
        response.raise_for_status()
        return VerificationResponse(**response.json())

    def verify_logic(self, query: str, provider: Optional[str] = None) -> LogicResponse:
        """
        Verify a logic puzzle.
        
        Args:
            query: The logic puzzle to solve.
            provider: Optional LLM provider.
            
        Returns:
            LogicResponse object.
        """
        payload = {"query": query}
        if provider:
            payload["provider"] = provider
            
        response = self.session.post(f"{self.base_url}/verify/logic", json=payload)
        response.raise_for_status()
        return LogicResponse(**response.json())

    def verify_fact(self, claim: str, context: str, provider: Optional[str] = None) -> FactResponse:
        """
        Verify a fact against a context.
        
        Args:
            claim: The statement to verify.
            context: The text context to verify against.
            provider: Optional LLM provider.
            
        Returns:
            FactResponse object.
        """
        payload = {
            "claim": claim,
            "context": context
        }
        if provider:
            payload["provider"] = provider
            
        response = self.session.post(f"{self.base_url}/verify/fact", json=payload)
        response.raise_for_status()
        return FactResponse(**response.json())
