"""
Debug script to test translation logic directly without API.
"""
import os
from qwed_new.core.translator import TranslationLayer

# Force Azure OpenAI
os.environ["ACTIVE_PROVIDER"] = "azure_openai"

def debug_translation():
    translator = TranslationLayer()
    query = "Find two integers x and y where x is greater than y and their sum is 10."
    
    print(f"Testing translation for: '{query}'")
    try:
        task = translator.translate_logic(query)
        print("✅ Success!")
        print(task)
    except Exception as e:
        print(f"❌ Failed: {e}")

if __name__ == "__main__":
    debug_translation()
