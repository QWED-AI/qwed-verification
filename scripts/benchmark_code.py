"""
QWED Code Verifier Benchmark - 40 HARDEST Questions

Tests LLM's ability to detect:
- SQL injection vulnerabilities
- XSS (Cross-Site Scripting)
- Code safety issues
- Syntax errors
- Security vulnerabilities
- Authentication flaws

Critical for banking, fintech, and enterprise security.
"""

import json
import time
import os
import requests
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Azure Claude API config - USE ENVIRONMENT VARIABLES
AZURE_ENDPOINT = os.getenv(
    "AZURE_ENDPOINT", 
    "https://your-resource.services.ai.azure.com/anthropic/v1/messages"
)
AZURE_API_KEY = os.getenv("AZURE_API_KEY", "")

if not AZURE_API_KEY:
    print("⚠️  Set AZURE_API_KEY environment variable to run benchmarks")

# 40 Code Verifier Questions
CODE_DATASET = [
    # === SQL INJECTION (12) ===
    {"id": 1, "domain": "sql_injection", "query": "Is this SQL safe? SELECT * FROM users WHERE id = '" + "user_input" + "'. SAFE or VULNERABLE?", "expected": "vulnerable", "trap": "String concatenation"},
    {"id": 2, "domain": "sql_injection", "query": "Query: SELECT * FROM users WHERE id = ?. Using parameterized query. SAFE or VULNERABLE?", "expected": "safe", "trap": "Parameterized query"},
    {"id": 3, "domain": "sql_injection", "query": "Input: admin'--. Query: SELECT * FROM users WHERE name = 'admin'--'. SAFE or VULNERABLE?", "expected": "vulnerable", "trap": "Comment injection"},
    {"id": 4, "domain": "sql_injection", "query": "Query: SELECT * FROM users WHERE id = CAST(? AS INT). SAFE or VULNERABLE?", "expected": "safe", "trap": "Type casting"},
    {"id": 5, "domain": "sql_injection", "query": "Query: 'SELECT * FROM ' + table_name + ' WHERE id = 1'. Table name from user. SAFE or VULNERABLE?", "expected": "vulnerable", "trap": "Dynamic table name"},
    {"id": 6, "domain": "sql_injection", "query": "ORM query: User.objects.filter(id=user_id). SAFE or VULNERABLE?", "expected": "safe", "trap": "ORM protection"},
    {"id": 7, "domain": "sql_injection", "query": "Query: SELECT * FROM users ORDER BY \" + user_input. SAFE or VULNERABLE?", "expected": "vulnerable", "trap": "ORDER BY injection"},
    {"id": 8, "domain": "sql_injection", "query": "Stored procedure: EXEC sp_GetUser @id = ?. SAFE or VULNERABLE?", "expected": "safe", "trap": "Stored procedure with param"},
    {"id": 9, "domain": "sql_injection", "query": "Query: SELECT * FROM users WHERE id IN (\" + ids.join(',') + \"'). SAFE or VULNERABLE?", "expected": "vulnerable", "trap": "IN clause injection"},
    {"id": 10, "domain": "sql_injection", "query": "Query with input validation: parseInt(user_id) before query. SAFE or VULNERABLE?", "expected": "safe", "trap": "Input validation"},
    {"id": 11, "domain": "sql_injection", "query": "MongoDB: db.users.find({name: user_input}). NoSQL injection possible? SAFE or VULNERABLE?", "expected": "vulnerable", "trap": "NoSQL injection"},
    {"id": 12, "domain": "sql_injection", "query": "Query: SELECT * FROM users WHERE id = $1 (PostgreSQL). SAFE or VULNERABLE?", "expected": "safe", "trap": "PostgreSQL params"},

    # === XSS (10) ===
    {"id": 13, "domain": "xss", "query": "HTML: <div>\" + user_name + \"</div>. No escaping. SAFE or VULNERABLE?", "expected": "vulnerable", "trap": "Unescaped output"},
    {"id": 14, "domain": "xss", "query": "React JSX: <div>{userName}</div>. Auto-escaped. SAFE or VULNERABLE?", "expected": "safe", "trap": "React auto-escape"},
    {"id": 15, "domain": "xss", "query": "innerHTML = user_input. SAFE or VULNERABLE?", "expected": "vulnerable", "trap": "innerHTML danger"},
    {"id": 16, "domain": "xss", "query": "textContent = user_input. SAFE or VULNERABLE?", "expected": "safe", "trap": "textContent safe"},
    {"id": 17, "domain": "xss", "query": "URL: /search?q=\" + encodeURIComponent(query). SAFE or VULNERABLE?", "expected": "safe", "trap": "URI encoding"},
    {"id": 18, "domain": "xss", "query": "onclick=\" + user_input. In HTML attribute. SAFE or VULNERABLE?", "expected": "vulnerable", "trap": "Event handler injection"},
    {"id": 19, "domain": "xss", "query": "CSP header: Content-Security-Policy: script-src 'self'. Additional XSS protection? YES or NO?", "expected": "yes", "trap": "CSP protection"},
    {"id": 20, "domain": "xss", "query": "Template: {{user_input}} in Angular. SAFE or VULNERABLE?", "expected": "safe", "trap": "Angular sanitization"},
    {"id": 21, "domain": "xss", "query": "dangerouslySetInnerHTML={{__html: user_input}} in React. SAFE or VULNERABLE?", "expected": "vulnerable", "trap": "React dangerous prop"},
    {"id": 22, "domain": "xss", "query": "HTTP-only cookie for session. XSS can steal it? YES or NO?", "expected": "no", "trap": "HTTP-only protection"},

    # === AUTH & SECURITY (10) ===
    {"id": 23, "domain": "auth", "query": "Password stored as MD5 hash. SECURE or INSECURE?", "expected": "insecure", "trap": "MD5 is broken"},
    {"id": 24, "domain": "auth", "query": "Password stored as bcrypt with salt. SECURE or INSECURE?", "expected": "secure", "trap": "bcrypt is good"},
    {"id": 25, "domain": "auth", "query": "JWT token in localStorage. SECURE or INSECURE?", "expected": "insecure", "trap": "XSS can steal"},
    {"id": 26, "domain": "auth", "query": "JWT token in HTTP-only cookie. More SECURE or INSECURE?", "expected": "secure", "trap": "HTTP-only better"},
    {"id": 27, "domain": "auth", "query": "API key in URL: /api?key=abc123. SECURE or INSECURE?", "expected": "insecure", "trap": "Key in logs"},
    {"id": 28, "domain": "auth", "query": "API key in Authorization header. SECURE or INSECURE?", "expected": "secure", "trap": "Header is better"},
    {"id": 29, "domain": "auth", "query": "CORS: Access-Control-Allow-Origin: *. SECURE or INSECURE?", "expected": "insecure", "trap": "Wildcard CORS"},
    {"id": 30, "domain": "auth", "query": "Rate limiting on login: 5 attempts per minute. Helps against bruteforce? YES or NO?", "expected": "yes", "trap": "Rate limiting"},
    {"id": 31, "domain": "auth", "query": "Password min length 6 chars, no complexity. SECURE or INSECURE?", "expected": "insecure", "trap": "Weak policy"},
    {"id": 32, "domain": "auth", "query": "2FA with TOTP (like Google Authenticator). Adds security? YES or NO?", "expected": "yes", "trap": "2FA benefit"},

    # === CODE SAFETY (8) ===
    {"id": 33, "domain": "code_safety", "query": "Python: eval(user_input). SAFE or DANGEROUS?", "expected": "dangerous", "trap": "eval is evil"},
    {"id": 34, "domain": "code_safety", "query": "Python: ast.literal_eval(user_input). SAFE or DANGEROUS?", "expected": "safe", "trap": "literal_eval safer"},
    {"id": 35, "domain": "code_safety", "query": "JavaScript: new Function(user_code). SAFE or DANGEROUS?", "expected": "dangerous", "trap": "Dynamic code"},
    {"id": 36, "domain": "code_safety", "query": "subprocess.run(['ls', user_input], shell=False). SAFE or DANGEROUS?", "expected": "safe", "trap": "shell=False safe"},
    {"id": 37, "domain": "code_safety", "query": "os.system('rm ' + filename). SAFE or DANGEROUS?", "expected": "dangerous", "trap": "Command injection"},
    {"id": 38, "domain": "code_safety", "query": "Path: os.path.join(base_dir, user_file). Path traversal possible? YES or NO?", "expected": "yes", "trap": "../ still works"},
    {"id": 39, "domain": "code_safety", "query": "pickle.loads(user_data). SAFE or DANGEROUS?", "expected": "dangerous", "trap": "Pickle RCE"},
    {"id": 40, "domain": "code_safety", "query": "json.loads(user_data). SAFE or DANGEROUS?", "expected": "safe", "trap": "JSON is safe"},
]

def call_claude(query: str) -> str:
    """Call Claude Opus 4.5"""
    headers = {
        "Content-Type": "application/json",
        "x-api-key": AZURE_API_KEY,
        "anthropic-version": "2023-06-01"
    }
    
    payload = {
        "model": "claude-opus-4-5",
        "max_tokens": 50,
        "temperature": 0,
        "system": """You are a security code reviewer. Answer with ONLY the keyword:
- SAFE or VULNERABLE for SQL/XSS
- SECURE or INSECURE for auth
- SAFE or DANGEROUS for code safety
- YES or NO for yes/no questions
Just the single word, nothing else.""",
        "messages": [{"role": "user", "content": query}]
    }
    
    response = requests.post(AZURE_ENDPOINT, headers=headers, json=payload, timeout=30)
    response.raise_for_status()
    return response.json()["content"][0]["text"].strip().lower()

def run_code_benchmark():
    print("=" * 70)
    print("🔐 QWED CODE VERIFIER BENCHMARK")
    print("=" * 70)
    print(f"Model: Claude Opus 4.5")
    print(f"Dataset: {len(CODE_DATASET)} security questions")
    print("-" * 70)
    
    results = {
        "by_domain": {
            "sql_injection": {"correct": 0, "wrong": 0},
            "xss": {"correct": 0, "wrong": 0},
            "auth": {"correct": 0, "wrong": 0},
            "code_safety": {"correct": 0, "wrong": 0},
        },
        "details": []
    }
    
    for item in CODE_DATASET:
        domain = item["domain"]
        print(f"\n[{item['id']}/{len(CODE_DATASET)}] [{domain.upper()}]")
        print(f"   Q: {item['query'][:60]}...")
        print(f"   Trap: {item['trap']}")
        
        try:
            claude = call_claude(item["query"])
            expected = item["expected"].lower()
            is_correct = expected in claude or claude == expected
            
            if is_correct:
                results["by_domain"][domain]["correct"] += 1
                print(f"   ✅ Claude: {claude}")
            else:
                results["by_domain"][domain]["wrong"] += 1
                print(f"   ❌ Claude: {claude} (expected: {expected})")
            
            results["details"].append({
                "id": item["id"], "domain": domain,
                "claude": claude, "expected": expected, "correct": is_correct
            })
        except Exception as e:
            print(f"   ⚠️ Error: {e}")
            results["by_domain"][domain]["wrong"] += 1
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 CODE VERIFIER RESULTS")
    print("=" * 70)
    
    total_correct = sum(d["correct"] for d in results["by_domain"].values())
    total_wrong = sum(d["wrong"] for d in results["by_domain"].values())
    
    print(f"\n{'Domain':<15} {'Correct':<10} {'Wrong':<10}")
    print("-" * 40)
    for domain, stats in results["by_domain"].items():
        print(f"{domain:<15} {stats['correct']:<10} {stats['wrong']:<10}")
    print("-" * 40)
    print(f"{'TOTAL':<15} {total_correct:<10} {total_wrong:<10}")
    
    accuracy = 100 * total_correct / len(CODE_DATASET)
    print(f"\n🔐 Claude Code Security: {total_correct}/{len(CODE_DATASET)} ({accuracy:.1f}%)")
    
    with open("benchmarks/code_benchmark_results.json", "w") as f:
        json.dump({"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "accuracy": f"{accuracy:.1f}%", "results": results}, f, indent=2)
    
    print("\n✅ Results saved to benchmarks/code_benchmark_results.json")
    return results

if __name__ == "__main__":
    os.makedirs("benchmarks", exist_ok=True)
    run_code_benchmark()
