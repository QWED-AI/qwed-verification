"""QWED is model-agnostic: the deployment files name no model.

``deploy/kubernetes/configmap.yaml`` set ``AZURE_OPENAI_DEPLOYMENT`` to
``gpt-4``. A provider with no model set reports the setting to fix
(``providers/base.py``'s ``configured_model``), so the files ship it empty.

The deciding check is by setting, not by name: every model or deployment
setting in a deployment file (``MODEL``, ``*_MODEL``, ``*_DEPLOYMENT``,
``model``, in any case) is empty, or refers to another variable in a form
the format substitutes: ``${NAME}`` with no default in a Compose file or in
a .env value outside single quotes, and ``$(NAME)`` in a Kubernetes ``env``
entry when an entry above it in the same list defines ``NAME`` from a
required Secret or ConfigMap key, or from another such reference. A key of
a Secret or ConfigMap that ``deploy/`` itself ships with a value is the
repository's own text, so it counts as written there. Anything
else, ``${NAME}`` in a ConfigMap included, is a literal value. YAML files
are read as YAML, and one that does not parse fails, so a quoted key, a
lowercase key, a Compose ``environment`` list and a Kubernetes ``env`` entry
(``name:`` with ``value:`` or ``valueFrom:``) are all seen; other files are
read line by line, and a value never runs on to the next line. A second check looks for
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
# Compose's merge tags where YAML puts a tag: right after a key's colon or a
# list dash, or after an anchor there. Text after a value's first character
# is the value itself.
COMPOSE_TAG = re.compile(
    r"(?m)((?::|^[ \t]*-)[ \t]+(?:&[^\s]+[ \t]+)?)!(?:reset|override)(?=[ \t]|$)"
)
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


def _secret_or_config_map(source, shipped):
    """"required" or "optional" for a valueFrom that reads a Secret or
    ConfigMap key, "shipped" when deploy/ itself ships that Secret or
    ConfigMap with a value for the key, else None; with the shipped value.
    A fieldRef or resourceFieldRef reads the pod's own manifest or limits,
    and a value deploy/ ships is the repository's own text."""
    if not isinstance(source, dict) or len(source) != 1:
        return None, None
    kind, selector = next(iter(source.items()))
    if kind not in ("secretKeyRef", "configMapKeyRef") or not isinstance(selector, dict):
        return None, None
    owner = ("Secret" if kind == "secretKeyRef" else "ConfigMap", selector.get("name"))
    value = shipped.get(owner, {}).get(selector.get("key"))
    if value not in (None, ""):
        return "shipped", value
    return ("optional" if selector.get("optional") is True else "required"), None


def _shipped_in(texts):
    """The Secrets and ConfigMaps the deployment files ship, as
    {(kind, name): {key: value}}, from (file name, text) pairs.

    Every Secret and ConfigMap counts, at any depth (a kind: List included)
    and in any namespace, and a key written with a value in any of them wins
    over the same key shipped empty elsewhere. So the check may call a
    reference written text when another namespace's copy has the value, but
    never takes a written value for the operator's."""
    shipped = {}

    def collect(node):
        if isinstance(node, dict):
            if node.get("kind") in ("Secret", "ConfigMap"):
                values = shipped.setdefault((node["kind"], (node.get("metadata") or {}).get("name")), {})
                for field in ("data", "stringData"):
                    for key, value in (node.get(field) or {}).items():
                        if values.get(key) in (None, ""):
                            values[key] = value
            for value in node.values():
                collect(value)
        elif isinstance(node, list):
            for item in node:
                collect(item)

    for name, text in texts:
        if ".yaml" in name or ".yml" in name:
            for document in yaml.safe_load_all(_untagged(name, text)):
                collect(document)
    return shipped


def _untagged(name, text):
    # Compose's merge tags, !reset and !override, mark how a value combines
    # with another file; the value itself is plain YAML.
    return COMPOSE_TAG.sub(r"\1", text) if "compose" in name else text


def _walk(node, found, context, shipped):
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and SETTING_KEY.match(key) and not isinstance(value, (dict, list)):
                found.append((key, value, context))
            _walk(value, found, context, shipped)
    elif isinstance(node, list):
        defined = []
        for item in node:
            if isinstance(item, str) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*(=|$)", item):
                key, _, value = item.partition("=")
                if SETTING_KEY.match(key):
                    found.append((key, value if "=" in item else None, context))
            elif isinstance(item, dict) and isinstance(item.get("name"), str):
                name = item["name"]
                here = (KUBERNETES_ENV, tuple(defined))
                source, shipped_value = _secret_or_config_map(item.get("valueFrom"), shipped)
                if SETTING_KEY.match(name) and ("value" in item or "valueFrom" in item):
                    # An env entry; valueFrom reads a Secret or a ConfigMap,
                    # and one that deploy/ ships reads the text written there.
                    if source == "shipped":
                        found.append((name, shipped_value, LITERAL))
                    else:
                        found.append((name, item.get("value"), here if context == LITERAL else context))
                # A later $(NAME) may refer to this entry only when its own
                # value is not written here: a required Secret or ConfigMap
                # key, or itself an allowed reference. A later entry with the
                # same name replaces the earlier value, so it replaces the
                # earlier standing too. An optional key is the exception: when
                # it is absent the earlier value stays, and when present it is
                # the operator's, so it keeps whatever standing NAME had (none,
                # if nothing above defines NAME: then $(NAME) stays as it is).
                # A key deploy/ ships with a value is written text.
                if source != "optional":
                    if name in defined:
                        defined.remove(name)
                    if source == "required" or (
                        "value" in item and item["value"] not in (None, "") and _allowed(item["value"], here)
                    ):
                        defined.append(name)
                _walk(item, found, context, shipped)
            else:
                _walk(item, found, context, shipped)


def _settings_in(name, text, shipped=None):
    """The model and deployment settings in one file, as (key, value,
    context). shipped holds the Secrets and ConfigMaps deploy/ ships."""
    found = []
    if ".yaml" in name or ".yml" in name:
        # A YAML file that does not parse fails the test, rather than being
        # read line by line, which would miss a name/value env entry.
        for document in yaml.safe_load_all(_untagged(name, text)):
            _walk(document, found, SUBSTITUTES if "compose" in name else LITERAL, shipped or {})
        return found
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
    ("deployment.yaml",
     ("env:\n  - name: DEPLOY_NAME\n    value: my-prod-dep\n"
      "  - name: AZURE_OPENAI_DEPLOYMENT\n    value: $(DEPLOY_NAME)\n"),
     [("AZURE_OPENAI_DEPLOYMENT", "$(DEPLOY_NAME)", (KUBERNETES_ENV, ()))]),
    ("deployment.yaml",
     ("env:\n  - name: DEPLOY_NAME\n    valueFrom: {configMapKeyRef: {name: c, key: k, optional: true}}\n"
      "  - name: AZURE_OPENAI_DEPLOYMENT\n    value: $(DEPLOY_NAME)\n"),
     [("AZURE_OPENAI_DEPLOYMENT", "$(DEPLOY_NAME)", (KUBERNETES_ENV, ()))]),
    ("deployment.yaml",
     ("env:\n  - name: A\n    valueFrom: {secretKeyRef: {name: s, key: k}}\n"
      "  - name: B\n    value: $(A)\n  - name: OPENAI_MODEL\n    value: $(B)\n"),
     [("OPENAI_MODEL", "$(B)", (KUBERNETES_ENV, ("A", "B")))]),
    ("deployment.yaml",
     ("env:\n  - name: A\n    valueFrom: {fieldRef: {fieldPath: \"metadata.labels['chosen']\"}}\n"
      "  - name: OPENAI_MODEL\n    value: $(A)\n"),
     [("OPENAI_MODEL", "$(A)", (KUBERNETES_ENV, ()))]),
    ("deployment.yaml",
     ("env:\n  - name: A\n    valueFrom: {secretKeyRef: {name: s, key: k}}\n"
      "  - name: A\n    value: custom-v1\n  - name: OPENAI_MODEL\n    value: $(A)\n"),
     [("OPENAI_MODEL", "$(A)", (KUBERNETES_ENV, ()))]),
    ("deployment.yaml",
     ("env:\n  - name: A\n    valueFrom: {secretKeyRef: {name: s, key: k}}\n"
      "  - name: A\n    valueFrom: {configMapKeyRef: {name: c, key: k, optional: true}}\n"
      "  - name: OPENAI_MODEL\n    value: $(A)\n"),
     [("OPENAI_MODEL", "$(A)", (KUBERNETES_ENV, ("A",)))]),
    ("docker-compose.yml", "environment: &env !override\n  - OPENAI_MODEL=custom-v1\n",
     [("OPENAI_MODEL", "custom-v1", SUBSTITUTES)]),
    ("docker-compose.yml", "env:\n  model: custom-v1\n", [("model", "custom-v1", SUBSTITUTES)]),
    ("docker-compose.yml", "environment: !override\n  - OPENAI_MODEL=custom-v1\nports: !reset []\n",
     [("OPENAI_MODEL", "custom-v1", SUBSTITUTES)]),
    ("docker-compose.yml", "environment: !reset\n  OPENAI_MODEL: !override custom-v1\n",
     [("OPENAI_MODEL", "custom-v1", SUBSTITUTES)]),
    ("docker-compose.yml", "environment:\n  - OPENAI_MODEL=${OPENAI_MODEL} !override\n",
     [("OPENAI_MODEL", "${OPENAI_MODEL} !override", SUBSTITUTES)]),
    ("docker-compose.yml", "environment:\n  OPENAI_MODEL: ${OPENAI_MODEL} !reset\n",
     [("OPENAI_MODEL", "${OPENAI_MODEL} !reset", SUBSTITUTES)]),
    ("docker-compose.yml", "e:\n  - !override OPENAI_MODEL=custom-v1\n",
     [("OPENAI_MODEL", "custom-v1", SUBSTITUTES)]),
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


def test_a_yaml_file_that_does_not_parse_fails():
    with pytest.raises(yaml.YAMLError):
        _settings_in("deployment.yaml", "env:\n  - name: OPENAI_MODEL\n    value: custom-v1\nbroken: [\n")


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


@pytest.mark.parametrize("shipped_value, settings", [
    ("custom-v1", [("OPENAI_MODEL", "custom-v1", LITERAL)]),
    ("", [("OPENAI_MODEL", None, (KUBERNETES_ENV, ()))]),
])
def test_a_key_that_deploy_ships_is_read_as_written(shipped_value, settings):
    shipped = _shipped_in([("configmap.yaml", f"kind: ConfigMap\nmetadata: {{name: c}}\ndata: {{CHOICE: '{shipped_value}'}}\n")])
    manifest = "env:\n  - name: OPENAI_MODEL\n    valueFrom: {configMapKeyRef: {name: c, key: CHOICE}}\n"

    assert _settings_in("deployment.yaml", manifest, shipped) == settings


@pytest.mark.parametrize("files", [
    # Two namespaces: the written value wins over the empty one, either order.
    [("a.yaml", "kind: ConfigMap\nmetadata: {name: c, namespace: one}\ndata: {CHOICE: ''}\n"),
     ("b.yaml", "kind: ConfigMap\nmetadata: {name: c, namespace: two}\ndata: {CHOICE: custom-v1}\n")],
    [("a.yaml", "kind: ConfigMap\nmetadata: {name: c, namespace: two}\ndata: {CHOICE: custom-v1}\n"),
     ("b.yaml", "kind: ConfigMap\nmetadata: {name: c, namespace: one}\ndata: {CHOICE: ''}\n")],
    # A ConfigMap inside a kind: List.
    [("list.yaml", "kind: List\nitems:\n  - kind: ConfigMap\n    metadata: {name: c}\n    data: {CHOICE: custom-v1}\n")],
])
def test_a_written_value_anywhere_in_deploy_counts(files):
    shipped = _shipped_in(files)
    manifest = "env:\n  - name: OPENAI_MODEL\n    valueFrom: {configMapKeyRef: {name: c, key: CHOICE}}\n"

    assert _settings_in("deployment.yaml", manifest, shipped) == [("OPENAI_MODEL", "custom-v1", LITERAL)]


def test_a_reference_to_a_key_that_deploy_ships_with_a_value_is_written_text():
    shipped = _shipped_in([("secret.yaml", "kind: Secret\nmetadata: {name: s}\nstringData: {K: custom-v1}\n")])
    manifest = (
        "env:\n  - name: A\n    valueFrom: {secretKeyRef: {name: s, key: K}}\n"
        "  - name: OPENAI_MODEL\n    value: $(A)\n"
    )

    [(_, value, context)] = _settings_in("deployment.yaml", manifest, shipped)
    assert not _allowed(value, context)


def test_every_model_setting_is_empty_or_refers_to_another_variable():
    texts = [(path.name, path.read_text(encoding="utf-8", errors="replace")) for path in _deploy_files()]
    shipped = _shipped_in(texts)
    settings = [
        (path.relative_to(ROOT).as_posix(), key, value, context)
        for path, (name, text) in zip(_deploy_files(), texts)
        for key, value, context in _settings_in(name, text, shipped)
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
