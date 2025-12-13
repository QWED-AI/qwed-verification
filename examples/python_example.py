"""
QWED Python SDK Example
"""
import os
from qwed import QwedClient

# 1. Initialize Client
# In production, use os.getenv("QWED_API_KEY")
client = QwedClient(api_key="demo_key", base_url="http://localhost:8000")

def run_math_example():
    print("\n--- Math Verification ---")
    query = "What is the compound interest on $1000 at 5% for 2 years?"
    print(f"Query: {query}")
    
    try:
        result = client.verify_natural_language(query)
        print(f"Status: {result.status}")
        print(f"Answer: {result.final_answer}")
        print(f"Confidence: {result.translation.get('confidence')}")
    except Exception as e:
        print(f"Error: {e}")

def run_logic_example():
    print("\n--- Logic Verification ---")
    query = "If all A are B, and some B are C, are some A definitely C?"
    print(f"Query: {query}")
    
    try:
        result = client.verify_logic(query)
        print(f"Status: {result.status}")
        if result.model:
            print(f"Counter-example: {result.model}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    print("Running QWED Examples...")
    run_math_example()
    run_logic_example()
