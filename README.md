# QWED: The Deterministic Verification Engine 🛡️
> *Trust, but Verify.*

QWED is a **Model-Agnostic Verification Layer** that sits between your LLM and your users. It translates probabilistic AI outputs into deterministic logic to guarantee correctness.

## 🚀 Features

### 🧠 Three Verification Engines
1.  **Math Verifier (SymPy)**: Verifies calculations (e.g., "What is 15% of 200?").
2.  **Logic Verifier (Z3)**: Solves logic puzzles and constraint problems (e.g., "Einstein's Riddle").
3.  **Statistical Verifier (Pandas)**: Verifies claims about tabular data (e.g., "Did sales increase?").
4.  **Fact Verifier (Citation)**: Verifies claims against text documents with exact citations.
5.  **Code Security Verifier (Static Analysis)**: Scans code for vulnerabilities and secrets.

### 🛡️ Enterprise-Grade Security
- **Prompt Injection Detection**: Blocks malicious inputs before they reach the LLM.
- **PII Redaction**: Automatically scrubs sensitive data from logs.
- **Sandboxed Execution**: Runs generated code in a restricted environment.

### 🔀 Model-Agnostic
- Switch between **Azure OpenAI (GPT-4)** and **Anthropic (Claude 3.5)** at runtime.

---

## 🛠️ Setup

### 1. Install Dependencies
```bash
pip install -e .
```

### 2. Configure Environment
Create a `.env` file:
```env
# Azure OpenAI
AZURE_OPENAI_ENDPOINT=...
AZURE_OPENAI_API_KEY=...
AZURE_OPENAI_DEPLOYMENT=...
AZURE_OPENAI_API_VERSION=...

# Anthropic (via Azure AI Foundry)
ANTHROPIC_ENDPOINT=...
ANTHROPIC_API_KEY=...
ANTHROPIC_DEPLOYMENT=...

# Default Provider
ACTIVE_PROVIDER=azure_openai
```

### 3. Run the API
```bash
uvicorn qwed_new.api.main:app --reload --port 8002
```

### 4. Run the Frontend
```bash
cd ../vector-meteoroid
npm run dev
```

---

## 📚 Documentation
- [API Reference](docs/API.md)
- [Architecture Guide](docs/ARCHITECTURE.md)
- [Deployment Guide](docs/DEPLOYMENT.md)

