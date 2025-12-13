#!/bin/bash
# Update code_verifier.py on remote server

# Backup original
cp ~/qwed_new/src/qwed_new/core/code_verifier.py ~/qwed_new/src/qwed_new/core/code_verifier.py.backup

# Add getattr to CRITICAL_FUNCTIONS (line 42)
sed -i '42s/"yaml.unsafe_load",/"yaml.unsafe_load",\n        "getattr",  # Can execute arbitrary methods/' ~/qwed_new/src/qwed_new/core/code_verifier.py

# Add WEAK_CRYPTO_FUNCTIONS after CRITICAL_FUNCTIONS
sed -i '/^    CRITICAL_FUNCTIONS = {/,/^    }/a \\n    # Weak cryptographic functions (CRITICAL for passwords)\n    WEAK_CRYPTO_FUNCTIONS = {\n        "hashlib.md5", "hashlib.sha1",  # Broken for passwords\n    }\n    \n    # Password-related variable names\n    PASSWORD_INDICATORS = {\n        "password", "passwd", "pwd", "pass",\n        "credential", "cred", "auth",\n        "secret", "token", "key"\n    }' ~/qwed_new/src/qwed_new/core/code_verifier.py

echo "Code verifier updated!"
echo "Restarting QWED service..."
sudo systemctl restart qwed
sleep 3
sudo systemctl status qwed
