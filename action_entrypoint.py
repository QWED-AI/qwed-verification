import os
import sys
from qwed_sdk import QWEDClient  # Source

def main():
    # 1. Capture Inputs from GitHub Action Environment
    api_key = os.environ.get("INPUT_API_KEY")
    query = os.environ.get("INPUT_QUERY")
    llm_output = os.environ.get("INPUT_LLM_OUTPUT")
    engine = os.environ.get("INPUT_ENGINE", "math") # Default to math

    if not query or not llm_output:
        print("❌ Error: 'query' and 'llm_output' are required inputs.")
        sys.exit(1)

    print(f"🚀 Starting QWED Verification (Engine: {engine})")

    # 2. Initialize Client
    try:
        # If API Key is missing, QWEDLocal (Open Source) might be used if configured
        client = QWEDClient(api_key=api_key)
    except Exception as e:
        print(f"❌ Client Initialization Failed: {e}")
        sys.exit(1)

    # 3. Route to the correct engine
    try:
        if engine == "math":
            result = client.verify_math(query=query, llm_output=llm_output)
        elif engine == "logic":
            result = client.verify_logic(query=query, llm_output=llm_output)
        elif engine == "code":
            result = client.verify_code(code=llm_output)
        else:
            print(f"❌ Unsupported engine: {engine}")
            sys.exit(1)

        # 4. Output Results to GitHub
        print(f"🔍 Verdict: {result.verified}")
        print(f"📝 Explanation: {result.explanation}")
        
        # Set Output for next steps in workflow
        with open(os.environ['GITHUB_OUTPUT'], 'a') as fh:
            fh.write(f"verified={str(result.verified).lower()}\n")
            fh.write(f"explanation={result.explanation}\n")

        # Fail the action if verification failed (optional, but good for CI gates)
        if not result.verified:
            sys.exit(1)

    except Exception as e:
        print(f"❌ Verification Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
