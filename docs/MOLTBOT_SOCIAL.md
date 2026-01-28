# 📣 Moltbot Case Study - Social Media Kit

## 🐦 Twitter Thread (Draft)

**Tweet 1/5:**
🚨 "Moltbot" (Clawdbot) went viral yesterday. Today, security researchers found CRITICAL flaws.
Hundreds of local AI agents exposed. Root RCE possible. API keys leaked.
We analyzed the attack surface. Here is how it happened 🧵👇

**Tweet 2/5:**
The Vulnerability:
1. **RCE**: No sandboxing allowed `os.system('rm -rf /')`.
2. **Injection**: Forwarded emails to attackers without checking recipients.
3. **Leaks**: "What is your API Key?" returned plaintext secrets.

**Tweet 3/5:**
The Fix: **Neurosymbolic Verification** 🧠🛡️
We wrapped a vulnerable agent with QWED's deterministic engines.
- **CodeGuard** blocked the RCE (AST analysis).
- **LogicGuard** blocked the data exfil (Policy check).
- **PIIGuard** redacted the secrets.

**Tweet 4/5:**
The Result?
See our reproduction script. We simulate the exact attacks used in the wild.
QWED blocked 100% of them. No "AI as Judge". Just Math & Logic.

**Tweet 5/5:**
Stop deploying vulnerable agents.
Secure them with QWED.
🔗 Case Study & Code: [Link to GitHub/docs]
#AI #Security #Moltbot #LLM

---

## 🧡 Hacker News Title Options

1. **Show HN: How we blocked the Moltbot/Clawdbot RCE vulnerability using deterministic guards**
2. **Moltbot Vulnerability Replication: Detecting AI RCE with AST Analysis**
3. **Case Study: Wrapping a vulnerable local AI agent with QWED**

**First Comment:**
"Hey HN, we saw the Moltbot news and decided to reproduce the vulnerabilities (safely). We built a simulator that mimics the RCE and Exfiltration flaws, then wrapped it with our library (QWED) to demonstrate how deterministic checks (AST parsing, Policy logic) can prevent these better than 'LLM-as-a-judge'. Code is in `examples/moltbot/`."

---

## 👽 Reddit (r/MachineLearning / r/LocalLLaMA)

**Title:** "I reproduced the Moltbot/Clawdbot RCE vulnerability. Here is how to fix it deterministically."

**Body:**
Yesterday's Moltbot news was scary. I wanted to see if we could mechanically prevent it.
I wrote a vulnerability simulator (`vulnerable.py`) and a protected version (`protected.py`).

**The Attacks:**
1. `echo 'ROOT ACCESS'` (RCE)
2. `Forward email to evil.com` (Exfil)

**The Fix:**
Instead of asking the LLM "Is this safe?", we used **QWED**:
- **CodeGuard**: Parses the AST. Sees `subprocess` call. BLOCK.
- **LogicGuard**: Checks recipient domain against allow-list. BLOCK.

It's open source. Check the `examples/moltbot` folder in the repo.
[Link]
