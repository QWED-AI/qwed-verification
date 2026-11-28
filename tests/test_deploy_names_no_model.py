"""QWED is model-agnostic: the deployment files name no model.

``deploy/kubernetes/configmap.yaml`` set ``AZURE_OPENAI_DEPLOYMENT`` to
``gpt-4``. A provider with no model set reports the setting to fix
(``providers/base.py``'s ``configured_model``), so the files ship it empty.

The deciding check is by setting, not by name: every model or deployment
setting in a deployment file (``MODEL``, ``*_MODEL``, ``*_DEPLOYMENT``,
``model``, in any case) is empty or taken from the environment with no
default. YAML files are read as YAML, so a quoted key, a lowercase key and a
Compose ``environment`` list are all seen; other files are read line by
line, and a value never runs on to the next line. A second check looks for
model names anywhere under ``deploy/``; a list of names is never complete,
so it only backs up the first.
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
    """A .env or YAML scalar: the quoted text if quoted, else the text
    before a # comment."""
    value = value.strip()
    if value[:1] in ("'", '"'):
        end = value.find(value[0], 1)
        if end > 0:
            return value[1:end]
    return re.sub(r"(?:^|[ \t]+)#.*$", "", value).strip()


def _walk(node, found):
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and SETTING_KEY.match(key) and not isinstance(value, (dict, list)):
                found.append((key, value))
            _walk(value, found)
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, str) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*(=|$)", item):
                key, _, value = item.partition("=")
                if SETTING_KEY.match(key):
                    found.append((key, value if "=" in item else None))
            else:
                _walk(item, found)


def _settings_in(name, text):
    """The model and deployment settings in one file, as (key, value)."""
    found = []
    if ".yaml" in name or ".yml" in name:
        try:
            for document in yaml.safe_load_all(text):
                _walk(document, found)
            return found
        except yaml.YAMLError:
            found = []
    for match in LINE.finditer(text):
        if SETTING_KEY.match(match.group(2)):
            found.append((match.group(2), _unquote(match.group(3))))
    return found


def _allowed(value):
    return value is None or str(value) == "" or bool(FROM_ENVIRONMENT.match(str(value)))


def _deploy_files():
    return [path for path in sorted(DEPLOY.rglob("*")) if path.is_file()]


@pytest.mark.parametrize("name, text, settings", [
    ("configmap.yaml", 'data:\n  AZURE_OPENAI_DEPLOYMENT: ""\n', [("AZURE_OPENAI_DEPLOYMENT", "")]),
    ("configmap.yaml", 'data:\n  "ANTHROPIC_MODEL": custom-v1\n', [("ANTHROPIC_MODEL", "custom-v1")]),
    ("compose.yml", "env:\n  model: custom-v1\n", [("model", "custom-v1")]),
    ("compose.yml", "e:\n  - OPENAI_MODEL=${OPENAI_MODEL:-gpt-4o}\n  - GEMINI_MODEL\n",
     [("OPENAI_MODEL", "${OPENAI_MODEL:-gpt-4o}"), ("GEMINI_MODEL", None)]),
    (".env.example", "OPENAI_MODEL=\nPORT=8000\n", [("OPENAI_MODEL", "")]),
    (".env.example", "MODEL=my-finetune\n", [("MODEL", "my-finetune")]),
    (".env.example", 'export AZURE_OPENAI_DEPLOYMENT="prod" # ours\n', [("AZURE_OPENAI_DEPLOYMENT", "prod")]),
    (".env.example", "AZURE_OPENAI_DEPLOYMENT= # set it\n", [("AZURE_OPENAI_DEPLOYMENT", "")]),
    (".env.example", "DATABASE_URL=x\nMODELS_DIR=/m\n", []),
])
def test_the_settings_are_read_in_each_format(name, text, settings):
    assert _settings_in(name, text) == settings


@pytest.mark.parametrize("value, allowed", [
    (None, True), ("", True), ("${AZURE_OPENAI_DEPLOYMENT}", True),
    ("${AZURE_OPENAI_DEPLOYMENT:?set it}", True), ("${OPENAI_MODEL:-}", True), ("${OPENAI_MODEL-}", True),
    ("${OPENAI_MODEL:-gpt-4o}", False), ("${OPENAI_MODEL-gpt-4o}", False), ("gpt-4", False),
    ("my-deployment", False), ("custom-v1", False),
])
def test_the_value_check(value, allowed):
    assert _allowed(value) is allowed


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
        (path.relative_to(ROOT).as_posix(), key, value)
        for path in _deploy_files()
        for key, value in _settings_in(path.name, path.read_text(encoding="utf-8", errors="replace"))
    ]

    assert ("deploy/kubernetes/configmap.yaml", "AZURE_OPENAI_DEPLOYMENT", "") in settings
    assert [s for s in settings if not _allowed(s[2])] == []


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
