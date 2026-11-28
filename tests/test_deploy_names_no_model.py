"""QWED is model-agnostic: the deployment files name no model.

``deploy/kubernetes/configmap.yaml`` set ``AZURE_OPENAI_DEPLOYMENT`` to
``gpt-4``. A provider with no model set reports the setting to fix
(``providers/base.py``'s ``configured_model``), so the files ship it empty.

The deciding check is by setting, not by name: every model or deployment
setting in a deployment file (``MODEL``, ``*_MODEL``, ``*_DEPLOYMENT``,
``model``, in any case) is empty, or taken from the environment with no
default where the format substitutes ``${NAME}``: Compose files, and .env
files outside single quotes. Kubernetes manifests substitute nothing, so
there ``${NAME}`` is a literal value. YAML files are read as YAML, so a
quoted key, a lowercase key, a Compose ``environment`` list and a
Kubernetes ``env`` entry (``name:`` and ``value:``) are all seen; other
files are read line by line, and a value never runs on to the next line. A
second check looks for model names anywhere under ``deploy/``; a list of
names is never complete, so it only backs up the first.
"""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"

SETTING_KEY = re.compile(
    r"^(?:[a-z0-9]+_)*(?:model|deployment)(?:_[a-z0-9]+)*$", re.IGNORECASE
)
# KEY=value or KEY: value on one line, with an optional list dash, `export`
# and quotes around the key.
LINE = re.compile(
    r"""^[ \t]*(?:-[ \t]*)?(?:export[ \t]+)?(["']?)([A-Za-z_][A-Za-z0-9_]*)\1[ \t]*[:=][ \t]*(.*?)[ \t]*$""",
    re.MULTILINE,
)
# Unset, empty, or ${NAME}, ${NAME:?message}, ${NAME?message}, ${NAME:-} or
# ${NAME-}: never a default after :- or -.
FROM_ENVIRONMENT = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*(?::?\?[^}]*|:?-)?\}$")

MODEL_NAME = re.compile(
    r"\b(?:gpt-?\d|o[1-9](?:-(?:mini|pro|preview))?\b|claude-\w|gemini-\w|llama-?\d"
    r"|mistral-\w|mixtral|deepseek|qwen\d?)",
    re.IGNORECASE,
)


def _unquote(value):
    """A .env scalar as (text, expands): the quoted text if quoted, else the
    text before a # comment. Single quotes keep ${NAME} as it is."""
    value = value.strip()
    if value[:1] in ("'", '"'):
        end = value.find(value[0], 1)
        if end > 0:
            return value[1:end], value[0] == '"'
    return re.sub(r"(?:^|[ \t]+)#.*$", "", value).strip(), True


def _walk(node, found, expands):
    if isinstance(node, dict):
        name = node.get("name")
        if isinstance(name, str) and SETTING_KEY.match(name) and ("value" in node or "valueFrom" in node):
            # A Kubernetes env entry; valueFrom reads a Secret or a ConfigMap.
            found.append((name, node.get("value"), expands))
        for key, value in node.items():
            if isinstance(key, str) and SETTING_KEY.match(key) and not isinstance(value, (dict, list)):
                found.append((key, value, expands))
            _walk(value, found, expands)
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, str) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*(=|$)", item):
                key, _, value = item.partition("=")
                if SETTING_KEY.match(key):
                    found.append((key, value if "=" in item else None, expands))
            else:
                _walk(item, found, expands)


def _settings_in(name, text):
    """The model and deployment settings in one file, as (key, value,
    expands), where expands says whether the format substitutes ${NAME}."""
    found = []
    if ".yaml" in name or ".yml" in name:
        try:
            for document in yaml.safe_load_all(text):
                _walk(document, found, expands="compose" in name)
            return found
        except yaml.YAMLError:
            found = []
    for match in LINE.finditer(text):
        if SETTING_KEY.match(match.group(2)):
            found.append((match.group(2), *_unquote(match.group(3))))
    return found


def _allowed(value, expands):
    if value is None or str(value) == "":
        return True
    return expands and bool(FROM_ENVIRONMENT.match(str(value)))


def _deploy_files():
    return [path for path in sorted(DEPLOY.rglob("*")) if path.is_file()]


@pytest.mark.parametrize("name, text, settings", [
    ("configmap.yaml", 'data:\n  AZURE_OPENAI_DEPLOYMENT: ""\n', [("AZURE_OPENAI_DEPLOYMENT", "", False)]),
    ("configmap.yaml", 'data:\n  "ANTHROPIC_MODEL": custom-v1\n', [("ANTHROPIC_MODEL", "custom-v1", False)]),
    ("deployment.yaml", "env:\n  - name: AZURE_OPENAI_DEPLOYMENT\n    value: my-prod-dep\n",
     [("AZURE_OPENAI_DEPLOYMENT", "my-prod-dep", False)]),
    ("deployment.yaml", "env:\n  - name: OPENAI_MODEL\n    valueFrom:\n      secretKeyRef: {name: s, key: k}\n",
     [("OPENAI_MODEL", None, False)]),
    ("docker-compose.yml", "env:\n  model: custom-v1\n", [("model", "custom-v1", True)]),
    ("docker-compose.yml", "e:\n  - OPENAI_MODEL=${OPENAI_MODEL:-gpt-4o}\n  - GEMINI_MODEL\n",
     [("OPENAI_MODEL", "${OPENAI_MODEL:-gpt-4o}", True), ("GEMINI_MODEL", None, True)]),
    (".env.example", "OPENAI_MODEL=\nPORT=8000\n", [("OPENAI_MODEL", "", True)]),
    (".env.example", "MODEL=my-finetune\n", [("MODEL", "my-finetune", True)]),
    (".env.example", 'export AZURE_OPENAI_DEPLOYMENT="prod" # ours\n', [("AZURE_OPENAI_DEPLOYMENT", "prod", True)]),
    (".env.example", "AZURE_OPENAI_DEPLOYMENT= # set it\n", [("AZURE_OPENAI_DEPLOYMENT", "", True)]),
    (".env.example", "OPENAI_MODEL='${OPENAI_MODEL}'\n", [("OPENAI_MODEL", "${OPENAI_MODEL}", False)]),
    (".env.example", "DATABASE_URL=x\nMODELS_DIR=/m\n", []),
])
def test_the_settings_are_read_in_each_format(name, text, settings):
    assert _settings_in(name, text) == settings


@pytest.mark.parametrize("value, expands, allowed", [
    (None, False, True), ("", False, True), ("${AZURE_OPENAI_DEPLOYMENT}", True, True),
    ("${AZURE_OPENAI_DEPLOYMENT:?set it}", True, True), ("${OPENAI_MODEL:-}", True, True),
    ("${OPENAI_MODEL-}", True, True),
    ("${AZURE_OPENAI_DEPLOYMENT}", False, False),
    ("${OPENAI_MODEL:-gpt-4o}", True, False), ("${OPENAI_MODEL-gpt-4o}", True, False),
    ("gpt-4", True, False), ("my-deployment", False, False), ("custom-v1", True, False),
])
def test_the_value_check(value, expands, allowed):
    assert _allowed(value, expands) is allowed


@pytest.mark.parametrize("text", [
    "gpt-4", "GPT-4", "gpt4", "gpt-4o-mini", "gpt-3.5-turbo", "o1", "o3", "o1-mini",
    "o1-pro", "openai-o3", "o3-preview", "claude-sonnet-4", "Claude-3-5-sonnet",
    "gemini-1.5-pro", "llama3", "Llama-2-70b", "mistral-large", "mixtral-8x7b",
    "DeepSeek-R1", "deepseek-chat", "qwen2", "Qwen-72B",
])
def test_the_name_pattern_finds_model_names(text):
    assert MODEL_NAME.search(f'MODEL: "{text}"')


@pytest.mark.parametrize("text", [
    "", "azure_openai", "https://your-resource.openai.azure.com/", "2023-05-15",
    "qwed-secrets", "redis://redis:6379/0", "my-deployment", "anthropic", "openai",
    "proto10", "ratio1",
])
def test_the_name_pattern_leaves_other_values(text):
    assert not MODEL_NAME.search(f'VALUE: "{text}"')


def test_every_model_setting_is_empty_or_from_the_environment():
    settings = [
        (path.relative_to(ROOT).as_posix(), key, value, expands)
        for path in _deploy_files()
        for key, value, expands in _settings_in(path.name, path.read_text(encoding="utf-8", errors="replace"))
    ]

    assert ("deploy/kubernetes/configmap.yaml", "AZURE_OPENAI_DEPLOYMENT", "", False) in settings
    assert [s for s in settings if not _allowed(s[2], s[3])] == []


def test_no_deployment_file_names_a_model():
    found = [
        (path.relative_to(ROOT).as_posix(), match.group(0))
        for path in _deploy_files()
        for match in MODEL_NAME.finditer(path.read_text(encoding="utf-8", errors="replace"))
    ]

    assert found == []


def test_the_configmap_leaves_the_azure_deployment_to_the_operator():
    config = yaml.safe_load((DEPLOY / "kubernetes" / "configmap.yaml").read_text(encoding="utf-8"))

    assert config["data"]["AZURE_OPENAI_DEPLOYMENT"] == ""
