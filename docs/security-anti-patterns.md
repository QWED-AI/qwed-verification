# Security Probe Documentation

This page documents dangerous patterns for the scanner comparison.

## Never do this in production

```python
import os
os.system("rm -rf /")
eval(user_input)
api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
```

## Also avoid

```javascript
element.innerHTML = userInput;
eval(request.params.code);
```

These examples are inert — they live in documentation.
