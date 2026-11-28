"""QWED is model-agnostic: the deployment files name no model.

``deploy/kubernetes/configmap.yaml`` set ``AZURE_OPENAI_DEPLOYMENT`` to
``gpt-4``. A provider with no model set reports the setting to fix
(``providers/base.py``'s ``configured_model``), so the files ship it empty.

The deciding check is by setting, not by name: every ``*_MODEL`` or
``*_DEPLOYMENT`` setting in a deployment file is empty or taken from the
environment with no default. A second check looks for model names anywhere
under ``deploy/``; a list of names is never complete, so it only backs up
the first.
"""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"

# KEY: value (YAML), KEY=value (.env and Compose lists), with an optional
# list dash in front.
SETTING = re.compile(
    r"^\s*(?:-\s*)?([A-Z][A-Z0-9_]*(?:_MODEL|_DEPLOYMENT)[A-Z0-9_]*)\s*[:=]\s*(.*?)\s*$",
    re.MULTILINE,
)
# Empty, or ${NAME}, ${NAME:?message} or ${NAME:-} with nothing after :-.
FROM_ENVIRONMENT = re.compile(r'^(?:""|\'\'|)$|^\$\{[A-Z][A-Z0-9_]*(?::\?[^}]*|:-)?\}$')

MODEL_NAME = re.compile(
    r"\b(?:gpt-?\d|o[1-9](?:-(?:mini|pro|preview))?\b|claude-\w|gemini-\w|llama-?\d"
    r"|mistral-\w|mixtral|deepseek|qwen\d?)",
    re.IGNORECASE,
)


def _deploy_files():
    return [path for path in sorted(DEPLOY.rglob("*")) if path.is_file()]


@pytest.mark.parametrize("line, value", [
    ('  AZURE_OPENAI_DEPLOYMENT: ""', '""'),
    ("AZURE_OPENAI_DEPLOYMENT=gpt-4", "gpt-4"),
    ("      - OPENAI_MODEL=${OPENAI_MODEL:-gpt-4o}", "${OPENAI_MODEL:-gpt-4o}"),
    ("ANTHROPIC_MODEL: my-model", "my-model"),
])
def test_the_setting_pattern_reads_each_format(line, value):
    assert [m.group(2) for m in SETTING.finditer(line)] == [value]


@pytest.mark.parametrize("value, allowed", [
    ('""', True), ("", True), ("${AZURE_OPENAI_DEPLOYMENT}", True),
    ("${AZURE_OPENAI_DEPLOYMENT:?set it}", True), ("${OPENAI_MODEL:-}", True),
    ("${OPENAI_MODEL:-gpt-4o}", False), ("gpt-4", False), ('"my-deployment"', False),
])
def test_the_value_check(value, allowed):
    assert bool(FROM_ENVIRONMENT.match(value)) is allowed


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
        (path.relative_to(ROOT).as_posix(), match.group(1), match.group(2))
        for path in _deploy_files()
        for match in SETTING.finditer(path.read_text(encoding="utf-8", errors="replace"))
    ]

    assert ("deploy/kubernetes/configmap.yaml", "AZURE_OPENAI_DEPLOYMENT", '""') in settings
    assert [s for s in settings if not FROM_ENVIRONMENT.match(s[2])] == []


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
