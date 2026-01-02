# LLM Provider Configuration Guide

Complete guide to configuring LLM providers for QWED.

## Quick Start

1. Copy `.env.example` to `.env`
2. Choose your LLM provider
3. Add your API key
4. Run QWED backend

```bash
cp .env.example .env
# Edit .env and add your API key
export ACTIVE_PROVIDER=anthropic
python -m qwed_api
```

---

## Supported Providers

### 1. OpenAI (Direct API)

**Best for:** Simple setup, standard OpenAI models

**Get API Key:** https://platform.openai.com/api-keys

**Configuration:**
```bash
ACTIVE_PROVIDER=openai
OPENAI_API_KEY=sk-proj-...
OPENAI_MODEL=gpt-4  # or gpt-3.5-turbo, gpt-4-turbo
```

**Python Code:**
```python
# In your backend code
from qwed_new.config import settings

print(settings.OPENAI_API_KEY)  # Verify it's loaded
```

---

### 2. Anthropic Claude (Direct API)

**Best for:** Latest Claude models, simple API

**Get API Key:** https://console.anthropic.com

**Configuration:**
```bash
ACTIVE_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-api03-...
ANTHROPIC_MODEL=claude-3-5-sonnet-20241022  # or claude-3-opus-20240229
```

**Available Models:**
- `claude-3-5-sonnet-20241022` (Recommended)
- `claude-3-opus-20240229`
- `claude-3-haiku-20240307`

---

### 3. Azure OpenAI

**Best for:** Enterprise deployments, compliance requirements

**Get Credentials:** https://portal.azure.com → Azure OpenAI Service

**Configuration:**
```bash
ACTIVE_PROVIDER=azure_openai
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_API_KEY=abc123...
AZURE_OPENAI_DEPLOYMENT=gpt-4  # Your deployment name in Azure
AZURE_OPENAI_API_VERSION=2024-02-01
```

**How to Get:**
1. Go to Azure Portal
2. Navigate to your Azure OpenAI resource
3. Click "Keys and Endpoint"  
4. Copy `KEY 1` and `Endpoint`

---

### 4. AWS Bedrock (Claude via AWS)

**Best for:** AWS infrastructure, unified billing

**Setup AWS Credentials:**

**Option A: AWS CLI**
```bash
aws configure
# Enter: Access Key ID, Secret Access Key, Region
```

**Option B: Environment Variables**
```bash
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1
AWS_BEDROCK_MODEL=anthropic.claude-3-5-sonnet-20241022-v2:0
```

**Prerequisites:**
1. AWS account with Bedrock access
2. Request model access in AWS Console
3. Install boto3: `pip install boto3`

---

### 5. Google Gemini

**Best for:** Google Cloud integration, Gemini models

**Get API Key:** https://makersuite.google.com/app/apikey

**Configuration:**
```bash
ACTIVE_PROVIDER=gemini
GOOGLE_API_KEY=AIzaSy...
GEMINI_MODEL=gemini-1.5-pro  # or gemini-1.5-flash
```

**Available Models:**
- `gemini-1.5-pro` (Best quality)
- `gemini-1.5-flash` (Fastest)
- `gemini-1.0-pro` (Legacy)

---

## Testing Your Configuration

### Step 1: Verify Environment Variables

```bash
# Load .env and check
python -c "from qwed_new.config import settings; print(f'Provider: {settings.ACTIVE_PROVIDER}')"
```

### Step 2: Run Backend Server

```bash
python -m qwed_api

# Should see:
# INFO: Started server process
# INFO: Uvicorn running on http://0.0.0.0:8000
```

### Step 3: Test with SDK

```python
from qwed import QWEDClient

client = QWEDClient(
    api_key="qwed_local",  # Local auth key
    base_url="http://localhost:8000"
)

result = client.verify("Is 2+2 equal to 4?")
print(result.verified)  # Should be True
```

---

## Common Issues

### Issue 1: "API key not found"

**Problem:**
```
Error: OPENAI_API_KEY environment variable not set
```

**Solution:**
```bash
# Check .env file exists
ls -la .env

# Verify it's loaded
python -c "from dotenv import load_dotenv; load_dotenv(); import os; print(os.getenv('OPENAI_API_KEY'))"
```

---

### Issue 2: "Provider not recognized"

**Problem:**
```
Error: Invalid provider: opnai
```

**Solution:**
Check spelling in `ACTIVE_PROVIDER`:
- ✅ `openai` (correct)
- ❌ `opnai` (typo)
- ❌ `OpenAI` (case-sensitive)

---

### Issue 3: Azure API version mismatch

**Problem:**
```
Error: The API version is not supported
```

**Solution:**
Update `AZURE_OPENAI_API_VERSION`:
```bash
AZURE_OPENAI_API_VERSION=2024-02-01  # Latest stable
```

---

## Security Best Practices

### ✅ DO:

1. **Use .env files**
   ```bash
   # .env file (gitignored)
   ANTHROPIC_API_KEY=sk-ant-...
   ```

2. **Add .env to .gitignore**
   ```bash
   echo ".env" >> .gitignore
   ```

3. **Rotate keys regularly**
   - Generate new keys every 90 days
   - Revoke old keys immediately

4. **Use different keys per environment**
   ```bash
   # Development
   OPENAI_API_KEY=sk-dev-...
   
   # Production
   OPENAI_API_KEY=sk-prod-...
   ```

### ❌ DON'T:

1. **Hardcode keys in code**
   ```python
   # ❌ NEVER DO THIS!
   api_key = "sk-proj-abc123..."
   ```

2. **Commit .env to Git**
   ```bash
   git add .env  # ❌ WRONG!
   ```

3. **Share keys via email/Slack**
   Use secure secret managers instead

4. **Use same key across all environments**
   Production keys should be separate

---

## Provider Comparison

| Provider | Pros | Cons | Best For |
|----------|------|------|----------|
| **OpenAI** | ✅ Simple, Latest GPT | ❌ Rate limits | Quick start |
| **Anthropic** | ✅ Long context, Safe | ❌ Newer | Production |
| **Azure OpenAI** | ✅ Enterprise SLAs | ❌ Complex setup | Enterprise |
| **AWS Bedrock** | ✅ Unified billing | ❌ Requires AWS | AWS users |
| **Google Gemini** | ✅ Fast, Free tier | ❌ Limited models | Testing |

---

## Multiple Providers (Advanced)

You can configure multiple providers and switch between them:

**Setup:**
```bash
# Configure all providers in .env
OPEN AI_API_KEY=sk-proj-...
ANTHROPIC_API_KEY=sk-ant-...
AZURE_OPENAI_ENDPOINT=https://...
```

**Switch dynamically:**
```python
import os

# Switch to Anthropic for this request
os.environ['ACTIVE_PROVIDER'] = 'anthropic'
result = client.verify("complex query")

# Switch to OpenAI for speed
os.environ['ACTIVE_PROVIDER'] = 'openai'
result = client.verify("simple query")
```

---

## Getting Help

**Provider-specific issues:**
- OpenAI: https://platform.openai.com/docs
- Anthropic: https://docs.anthropic.com
- Azure: https://learn.microsoft.com/azure/ai-services/openai/
- AWS: https://docs.aws.amazon.com/bedrock/
- Gemini: https://ai.google.dev/docs

**QWED issues:**
- GitHub: https://github.com/QWED-AI/qwed-verification/issues
- Discussions: https://github.com/QWED-AI/qwed-verification/discussions

---

**Next:** [Running the Backend Server](../README.md#running-the-backend)
