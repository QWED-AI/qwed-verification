"""
Verification script for Phase 2.
Tests the TranslationLayer with the configured provider.
"""

import os
from qwed_new.core.translator import TranslationLayer

def test_translation():
    print(f"Testing with provider: {os.getenv('ACTIVE_PROVIDER', 'default (azure_openai)')}")
    translator = TranslationLayer()
    
    query = "What is 10 + 10?"
    print(f"Query: {query}")
    
    try:
        result = translator.translate(query)
        print("✅ Success!")
        print(f"Expression: {result.expression}")
        print(f"Answer: {result.claimed_answer}")
        print(f"Provider used: {translator.provider.__class__.__name__}")
    except Exception as e:
        print(f"❌ Failed: {e}")

if __name__ == "__main__":
    test_translation()
