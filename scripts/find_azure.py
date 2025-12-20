import anthropic
import inspect

print("Searching for Azure/Foundry in anthropic package...")
for name, obj in inspect.getmembers(anthropic):
    if "Azure" in name or "Foundry" in name:
        print(f"Found: {name}")

# Also check inside resources if possible
try:
    from anthropic import resources
    for name, obj in inspect.getmembers(resources):
        if "Azure" in name or "Foundry" in name:
            print(f"Found in resources: {name}")
except:
    pass
