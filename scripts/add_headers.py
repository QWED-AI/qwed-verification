import os
from pathlib import Path

COPYRIGHT_HEADER = """# Copyright (c) 2024-2026 QWED Team
# SPDX-License-Identifier: Apache-2.0

"""

def add_header(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if "Copyright (c)" in content or "SPDX-License-Identifier" in content:
            print(f"Skipping {filepath} (Header present)")
            return

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(COPYRIGHT_HEADER + content)
        print(f"Updated {filepath}")
    except (OSError, UnicodeDecodeError) as e:
        print(f"Error processing {filepath}: {e}")

TARGET_FILES = [
    r"src/qwed_new/__init__.py",
    r"src/qwed_new/core/logic_verifier.py",
    r"qwed_sdk/cli.py",
    r"qwed_sdk/__init__.py",
    r"tests/security/test_injection.py"
]

if __name__ == "__main__":
    # Get the repo root (parent of 'scripts' directory)
    base_dir = Path(__file__).resolve().parent.parent
    
    for relative_path in TARGET_FILES:
        full_path = base_dir / relative_path
        if full_path.exists():
            add_header(full_path)
        else:
            print(f"File not found: {full_path}")
