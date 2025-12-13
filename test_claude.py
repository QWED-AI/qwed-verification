import os
from dotenv import load_dotenv
from anthropic import AnthropicFoundry

# Load environment variables
load_dotenv()

print("Testing Claude API Connection (AnthropicFoundry)...")
print("-" * 30)

try:
    endpoint = os.getenv("ANTHROPIC_ENDPOINT")
    api_key = os.getenv("ANTHROPIC_API_KEY")
    deployment = os.getenv("ANTHROPIC_DEPLOYMENT")

    print(f"Endpoint: {endpoint}")
    print(f"Deployment: {deployment}")

    client = AnthropicFoundry(
        api_key=api_key,
        base_url=endpoint,
    )

    message = client.messages.create(
        model=deployment,
        messages=[
            {"role": "user", "content": "Hello! Are you working?"}
        ],
        max_tokens=100,
    )

    print("-" * 30)
    print("✅ Success! Response from Claude:")
    print(message.content[0].text)

except Exception as e:
    print("-" * 30)
    print("❌ Error:")
    print(e)
