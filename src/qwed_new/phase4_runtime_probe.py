"""QWED probe: RUNTIME_CODE file exercising every Python engine.

Intentionally vulnerable — exists only on this test branch to compare
scanner coverage across QWED, Snyk, SonarQube, Greptile, Sentry, CodeRabbit.
"""

import os
import pickle
import subprocess
import yaml
import random
import base64

# --- Secrets: documented example values only ---
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS docs example key
STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"  # Stripe docs example key
prod_api_secret_key = "xK9mQ2vL8nR4pW7yT3uI6oE1sA5dF8gH3jK"  # high-entropy generic
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"


def run_dynamic(user_expr):
    return eval(user_expr)  # dynamic execution


def run_shell(host):
    os.system(f"ping -c1 {host}")  # shell execution
    subprocess.call(f"nslookup {host}", shell=True)  # shell=True
    subprocess.run(["dig", host])  # external process


def deserialize(blob):
    return pickle.loads(blob)  # unsafe deserialization


def load_config(text):
    return yaml.load(text)  # yaml.load without Loader


def get_user(conn, username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return conn.execute(query)  # SQL interpolation


def session_token():
    return random.randint(100000, 999999)  # insecure random


def obfuscated_exec():
    payload = base64.b64decode("cHJpbnQoMSk=")
    fn = getattr(__builtins__, "exec")
    fn(payload)


def tainted():
    expression = input("expr: ")
    return eval(expression)  # taint: input -> eval
