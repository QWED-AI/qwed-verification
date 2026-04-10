#!/bin/bash
# Update code_verifier.py on remote server

# Backup original
/bin/cp ~/qwed_new/src/qwed_new/core/code_verifier.py ~/qwed_new/src/qwed_new/core/code_verifier.py.backup

# Add getattr to CRITICAL_FUNCTIONS
/bin/sed -i 's/"yaml\.unsafe_load",/"yaml.unsafe_load",\n        "getattr",  # Can execute arbitrary methods/' ~/qwed_new/src/qwed_new/core/code_verifier.py

# Add WEAK_CRYPTO_FUNCTIONS after CRITICAL_FUNCTIONS
/bin/sed -i '/^    CRITICAL_FUNCTIONS = {/,/^    }/{ /^    }/a\
\
    # Weak cryptographic functions (CRITICAL for passwords)\
    WEAK_CRYPTO_FUNCTIONS = {\
        "hashlib.md5", "hashlib.sha1",  # Broken for passwords\
    }\
\
    # Password-related variable names\
    PASSWORD_INDICATORS = {\
        "password", "passwd", "pwd", "pass",\
        "credential", "cred", "auth",\
        "secret", "token", "key"\
    }\
}' ~/qwed_new/src/qwed_new/core/code_verifier.py

/bin/echo "Code verifier updated!"
/bin/echo "Restarting QWED service..."
/bin/systemctl restart qwed
/bin/sleep 3
/bin/systemctl is-active --quiet qwed || { /bin/systemctl --no-pager status qwed; exit 1; }
