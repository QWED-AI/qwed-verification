import os
import shutil
import json

# Configuration
SOURCE_DIR = r"C:\Users\rahul\.gemini\antigravity\playground\vector-meteoroid\qwed_new\benchmarks\deep_suite"
DEST_DIR = r"C:\Users\rahul\.gemini\antigravity\playground\vector-meteoroid\qwed_new\opensource_release"
SENSITIVE_STRINGS = {
    "qwed_live_VJO2vWhLgZnuXwIePn_s5o2-MTFncN2KJZJAf2jiuOI": "YOUR_API_KEY_HERE",
    "http://13.71.22.94:8000": "http://localhost:8000",
    "13.71.22.94": "SERVER_IP",
    r"C:\Users\rahul\.gemini\antigravity\playground\vector-meteoroid\qwed_new": "/path/to/project",
    r"C:\\Users\\rahul\\.gemini\\antigravity\\playground\\vector-meteoroid\\qwed_new": "/path/to/project",
    r"C:\Users\rahul\AppData\Local\Programs\Python\Python311\python.exe": "python",
    "rahul": "user"
}

FILES_TO_PROCESS = [
    "fact_engine_tests.py",
    "code_engine_tests.py",
    "sql_engine_tests.py",
    "stats_engine_tests.py",
    "reasoning_engine_tests.py",
    "run_all_engine_tests.py",
    "adversarial_math_tests.py",
    "adversarial_logic_tests.py",
    "fact_engine_report.json",
    "code_engine_report.json",
    "sql_engine_report.json",
    "stats_engine_report.json",
    "reasoning_engine_report.json",
    "extreme_adversarial_report.json"
]

def sanitize_content(content):
    for sensitive, replacement in SENSITIVE_STRINGS.items():
        content = content.replace(sensitive, replacement)
    return content

def main():
    if not os.path.exists(DEST_DIR):
        os.makedirs(DEST_DIR)
        print(f"Created directory: {DEST_DIR}")

    for filename in FILES_TO_PROCESS:
        src_path = os.path.join(SOURCE_DIR, filename)
        dest_path = os.path.join(DEST_DIR, filename)
        
        if os.path.exists(src_path):
            print(f"Processing {filename}...")
            try:
                with open(src_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                cleaned_content = sanitize_content(content)
                
                with open(dest_path, 'w', encoding='utf-8') as f:
                    f.write(cleaned_content)
                print(f"✅ Saved to {dest_path}")
            except Exception as e:
                print(f"❌ Error processing {filename}: {e}")
        else:
            print(f"⚠️ File not found: {src_path}")

    # Create a README for the release
    readme_content = """# AI Safety Benchmark Suite

This repository contains the adversarial test suite used to benchmark "God-Tier" LLMs (Claude Opus 4.5, Sonnet 3.5) against the QWED Verification Layer.

## Contents

### Test Scripts
- `fact_engine_tests.py`: Tests for subtle misinformation and fact verification.
- `code_engine_tests.py`: Security tests for malicious code generation (eval, exec, file I/O).
- `sql_engine_tests.py`: Tests for SQL injection and schema validation.
- `stats_engine_tests.py`: Tests for statistical analysis and code execution.
- `reasoning_engine_tests.py`: Tests for logic puzzles and reasoning capabilities.
- `adversarial_math_tests.py`: Advanced math and financial scenarios (Indian Tax, SIP, etc.).

### Reports
- `*_report.json`: Actual results from our testing, showing where raw LLMs failed and the Verification Layer succeeded.

## Usage

1. Install dependencies: `pip install requests`
2. Set your API URL and Key in the scripts.
3. Run the tests: `python run_all_engine_tests.py`
"""
    with open(os.path.join(DEST_DIR, "README.md"), 'w', encoding='utf-8') as f:
        f.write(readme_content)
    print(f"✅ Created README.md")

if __name__ == "__main__":
    main()
