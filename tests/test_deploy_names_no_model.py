"""QWED is model-agnostic: the deployment files name no model.

``deploy/kubernetes/configmap.yaml`` set ``AZURE_OPENAI_DEPLOYMENT`` to
``gpt-4``. A provider with no model set reports the setting to fix
(``providers/base.py``'s ``configured_model``), so the files ship it empty.

The deciding check is by setting, not by name: every model or deployment
setting in a deployment file (``MODEL``, ``*_MODEL``, ``*_DEPLOYMENT``,
``model``, in any case) is empty, or refers to another variable in a form
the format substitutes: ``${NAME}`` with no default in a Compose file or in
a .env value outside single quotes, and ``$(NAME)`` in a Kubernetes ``env``
entry when an entry above it in the same list defines ``NAME``. Anything
else, ``${NAME}`` in a ConfigMap included, is a literal value. YAML files
are read as YAML, so a quoted key, a lowercase key, a Compose
``environment`` list and a Kubernetes ``env`` entry (``name:`` with
``value:`` or ``valueFrom:``) are all seen; other files are read line by
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

# Where a setting's value is read: a format that substitutes ${NAME}, one
# that takes the value as written, or a Kubernetes env entry together with
# the names the entries above it define.
SUBSTITUTES = "substitutes"
LITERAL = "literal"
KUBERNETES_ENV = "kubernetes-env"

SETTING_KEY = re.compile(
    r"^(?:[a-z0-9]+_)*(?:model|deployment)(?:_[a-z0-9]+)*$", re.IGNORECASE
)
# KEY=value or KEY: value on one line, with an optional list dash, `export`
# and quotes around the key.
LINE = re.compile(
    r"""^[ \t]*(?:-[ \t]*)?(?:export[ \t]+)?(["']?)([A-Za-z_][A-Za-z0-9_]*)\1[ \t]*[:=][ \t]*(.*?)[ \t]*$""",
    re.MULTILINE,
)
# ${NAME}, ${NAME:?message}, ${NAME?message}, ${NAME:-} or ${NAME-}: never a
# default after :- or -.
FROM_ENVIRONMENT = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*(?::?\?[^}]*|:?-)?\}$")
# A Kubernetes dependent variable: $(NAME). $$(NAME) is a literal.
KUBERNETES_REFERENCE = re.compile(r"^\$\(([A-Za-z_][A-Za-z0-9_]*)\)$")

MODEL_NAME = re.compile(
    r"\b(?:gpt-?\d|o[1-9](?:-(?:mini|pro|preview))?\b|claude-\w|gemini-\w|llama-?\d"
    r"|mistral-\w|mixtral|deepseek|qwen\d?)",
    re.IGNORECASE,
)


def _unquote(value):
    """A .env scalar as (text, context): the quoted text if quoted, else the
    text before a # comment. Single quotes keep ${NAME} as it is."""
    value = value.strip()
    if value[:1] in ("'", '"'):
        end = value.find(value[0], 1)
        if end > 0:
            return value[1:end], SUBSTITUTES if value[0] == '"' else LITERAL
    return re.sub(r"(?:^|[ \t]+)#.*$", "", value).strip(), SUBSTITUTES


def _walk(node, found, context):
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and SETTING_KEY.match(key) and not isinstance(value, (dict, list)):
                found.append((key, value, context))
            _walk(value, found, context)
    elif isinstance(node, list):
        defined = []
        for item in node:
            if isinstance(item, str) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*(=|$)", item):
                key, _, value = item.partition("=")
                if SETTING_KEY.match(key):
                    found.append((key, value if "=" in item else None, context))
            elif isinstance(item, dict) and isinstance(item.get("name"), str):
                name = item["name"]
                if SETTING_KEY.match(name) and ("value" in item or "valueFrom" in item):
                    # An env entry; valueFrom reads a Secret or a ConfigMap.
                    entry = (KUBERNETES_ENV, tuple(defined)) if context == LITERAL else context
                    found.append((name, item.get("value"), entry))
                defined.append(name)
                _walk(item, found, context)
            else:
                _walk(item, found, context)


def _settings_in(name, text):
    """The model and deployment settings in one file, as (key, value,
    context)."""
    found = []
    if ".yaml" in name or ".yml" in name:
        try:
            for document in yaml.safe_load_all(text):
                _walk(document, found, SUBSTITUTES if "compose" in name else LITERAL)
            return found
        except yaml.YAMLError:
            found = []
    for match in LINE.finditer(text):
        if SETTING_KEY.match(match.group(2)):
            found.append((match.group(2), *_unquote(match.group(3))))
    return found


def _allowed(value, context):
    if value is None or str(value) == "":
        return True
    text = str(value)
    if context == SUBSTITUTES:
        return bool(FROM_ENVIRONMENT.match(text))
    if isinstance(context, tuple) and context[0] == KUBERNETES_ENV:
        reference = KUBERNETES_REFERENCE.match(text)
        return bool(reference) and reference.group(1) in context[1]
    return False


def _deploy_files():
    return [path for path in sorted(DEPLOY.rglob("*")) if path.is_file()]


@pytest.mark.parametrize("name, text, settings", [
    ("configmap.yaml", 'data:\n  AZURE_OPENAI_DEPLOYMENT: ""\n', [("AZURE_OPENAI_DEPLOYMENT", "", LITERAL)]),
    ("configmap.yaml", 'data:\n  "ANTHROPIC_MODEL": custom-v1\n', [("ANTHROPIC_MODEL", "custom-v1", LITERAL)]),
    ("deployment.yaml", "env:\n  - name: AZURE_OPENAI_DEPLOYMENT\n    value: my-prod-dep\n",
     [("AZURE_OPENAI_DEPLOYMENT", "my-prod-dep", (KUBERNETES_ENV, ()))]),
    ("deployment.yaml", "env:\n  - name: OPENAI_MODEL\n    valueFrom:\n      secretKeyRef: {name: s, key: k}\n",
     [("OPENAI_MODEL", None, (KUBERNETES_ENV, ()))]),
    ("deployment.yaml",
     ("env:\n  - name: DEPLOY_NAME\n    valueFrom: {secretKeyRef: {name: s, key: k}}\n"
      "  - name: AZURE_OPENAI_DEPLOYMENT\n    value: $(DEPLOY_NAME)\n"),
     [("AZURE_OPENAI_DEPLOYMENT", "$(DEPLOY_NAME)", (KUBERNETES_ENV, ("DEPLOY_NAME",)))]),
    ("docker-compose.yml", "env:\n  model: custom-v1\n", [("model", "custom-v1", SUBSTITUTES)]),
    ("docker-compose.yml", "e:\n  - OPENAI_MODEL=${OPENAI_MODEL:-gpt-4o}\n  - GEMINI_MODEL\n",
     [("OPENAI_MODEL", "${OPENAI_MODEL:-gpt-4o}", SUBSTITUTES), ("GEMINI_MODEL", None, SUBSTITUTES)]),
    (".env.example", "OPENAI_MODEL=\nPORT=8000\n", [("OPENAI_MODEL", "", SUBSTITUTES)]),
    (".env.example", "MODEL=my-finetune\n", [("MODEL", "my-finetune", SUBSTITUTES)]),
    (".env.example", 'export AZURE_OPENAI_DEPLOYMENT="prod" # ours\n',
     [("AZURE_OPENAI_DEPLOYMENT", "prod", SUBSTITUTES)]),
    (".env.example", "AZURE_OPENAI_DEPLOYMENT= # set it\n", [("AZURE_OPENAI_DEPLOYMENT", "", SUBSTITUTES)]),
    (".env.example", "OPENAI_MODEL='${OPENAI_MODEL}'\n", [("OPENAI_MODEL", "${OPENAI_MODEL}", LITERAL)]),
    (".env.example", "DATABASE_URL=x\nMODELS_DIR=/m\n", []),
])
def test_the_settings_are_read_in_each_format(name, text, settings):
    assert _settings_in(name, text) == settings


@pytest.mark.parametrize("value, context, allowed", [
    (None, LITERAL, True), ("", LITERAL, True),
    ("${AZURE_OPENAI_DEPLOYMENT}", SUBSTITUTES, True),
    ("${AZURE_OPENAI_DEPLOYMENT:?set it}", SUBSTITUTES, True),
    ("${OPENAI_MODEL:-}", SUBSTITUTES, True), ("${OPENAI_MODEL-}", SUBSTITUTES, True),
    ("${AZURE_OPENAI_DEPLOYMENT}", LITERAL, False),
    ("${OPENAI_MODEL:-gpt-4o}", SUBSTITUTES, False), ("${OPENAI_MODEL-gpt-4o}", SUBSTITUTES, False),
    ("$(DEPLOY_NAME)", (KUBERNETES_ENV, ("DEPLOY_NAME",)), True),
    ("$(DEPLOY_NAME)", (KUBERNETES_ENV, ()), False),
    ("$(DEPLOY_NAME)", LITERAL, False),
    ("$$(DEPLOY_NAME)", (KUBERNETES_ENV, ("DEPLOY_NAME",)), False),
    ("${DEPLOY_NAME}", (KUBERNETES_ENV, ("DEPLOY_NAME",)), False),
    ("gpt-4", SUBSTITUTES, False), ("my-deployment", LITERAL, False),
    ("custom-v1", (KUBERNETES_ENV, ()), False),
])
def test_the_value_check(value, context, allowed):
    assert _allowed(value, context) is allowed


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


def test_every_model_setting_is_empty_or_refers_to_another_variable():
    settings = [
        (path.relative_to(ROOT).as_posix(), key, value, context)
        for path in _deploy_files()
        for key, value, context in _settings_in(path.name, path.read_text(encoding="utf-8", errors="replace"))
    ]

    assert ("deploy/kubernetes/configmap.yaml", "AZURE_OPENAI_DEPLOYMENT", "", LITERAL) in settings
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
