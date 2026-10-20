"""#467: the published image ran the GitHub Action, not the API server, and
deploy/docker-compose.yml could not build.

The Dockerfile now has a ``server`` target (uvicorn, every server dependency
hash-pinned) and keeps the Action as the default, last target, which
action.yml builds. Compose builds the server target from the repository
root, and every file it mounts exists. These tests check the files; the
"Docker images" workflow builds and starts the images.
"""

import re
from pathlib import Path

import pytest
import yaml

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
COMPOSE_PATH = ROOT / "deploy" / "docker-compose.yml"
COMPOSE = yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))
SERVER_LOCK = (ROOT / "requirements-server.txt").read_text(encoding="utf-8")

SERVER_SECRETS = (
    "QWED_CORS_ORIGINS",
    "API_KEY_SECRET",
    "QWED_JWT_SECRET_KEY",
    "QWED_API_KEY_LOOKUP_SECRET",
    "QWED_AUDIT_SECRET_KEY",
)


def _stages():
    """Split the Dockerfile into {stage name: instructions}, in order."""
    stages = {}
    current = None
    for line in DOCKERFILE.splitlines():
        match = re.match(r"FROM\s+\S+\s+AS\s+(\S+)", line, re.IGNORECASE)
        if match:
            current = match.group(1)
            stages[current] = []
        elif current and line.strip() and not line.lstrip().startswith("#"):
            stages[current].append(line)
    return stages


def _normalise(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _locked_packages():
    return {_normalise(m.group(1)) for m in re.finditer(r"^([A-Za-z0-9_.-]+)==", SERVER_LOCK, re.M)}


# ---------- Dockerfile ----------

def test_the_action_is_the_last_stage_so_action_yml_still_builds_it():
    stages = list(_stages())
    assert stages == ["base", "server", "action"]
    action = "\n".join(_stages()["action"])
    assert 'ENTRYPOINT ["/entrypoint.sh"]' in action
    assert "python /action_entrypoint.py" in action


def test_action_yml_builds_the_dockerfile_without_a_target():
    spec = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert spec["runs"]["image"] == "Dockerfile"


def test_the_server_stage_runs_uvicorn_as_a_non_root_user():
    server = "\n".join(_stages()["server"])

    assert 'ENTRYPOINT ["python", "-m", "uvicorn", "qwed_new.api.main:app"]' in server
    assert re.search(r"^USER qwed$", server, re.M)
    assert "--require-hashes -r /app/requirements-server.txt" in server
    assert "COPY src/qwed_new /app/qwed_new/" in server
    assert "COPY qwed_sdk /app/qwed_sdk/" in server


def test_the_health_check_follows_the_port_uvicorn_listens_on():
    # uvicorn and the health check both read UVICORN_PORT, so changing the
    # port with -e UVICORN_PORT=... keeps the container healthy.
    server = "\n".join(_stages()["server"])

    assert re.search(r"ENV UVICORN_HOST=0\.0\.0\.0 \\\s+UVICORN_PORT=8000", server)
    assert not re.search(r"^CMD ", server, re.M)
    assert "--port" not in server
    healthcheck = server[server.index("HEALTHCHECK"):server.index("ENTRYPOINT")]
    assert "os.environ.get('UVICORN_PORT', '8000')" in healthcheck
    assert "http://127.0.0.1:{port}/health" in healthcheck


def test_the_dockerfile_binds_all_interfaces_in_exactly_one_place():
    # .qwed.yml suppresses bind-all-interfaces for the whole root Dockerfile,
    # because a suppression cannot name a line. This keeps it to the one
    # intended bind: a second 0.0.0.0 has to change this test and be reviewed.
    lines = [line for line in DOCKERFILE.splitlines() if "0.0.0.0" in line]

    assert lines == ["ENV UVICORN_HOST=0.0.0.0 \\"]
    assert "::" not in DOCKERFILE.replace("http://", "")


def test_the_server_stage_does_not_inherit_the_action_entrypoint():
    server = "\n".join(_stages()["server"])
    assert "entrypoint.sh" not in server
    assert "action_entrypoint" not in server


# ---------- requirements-server.txt ----------

def test_every_locked_server_requirement_is_hash_pinned():
    blocks = re.split(r"\n(?=[A-Za-z0-9_.-]+==)", SERVER_LOCK.split("\n", 2)[-1])
    requirements = [b for b in blocks if re.match(r"[A-Za-z0-9_.-]+==", b)]
    assert requirements
    for block in requirements:
        assert "--hash=sha256:" in block, block.splitlines()[0]


@pytest.mark.skipif(tomllib is None, reason="needs tomllib")
def test_the_server_lock_covers_the_core_dependencies_and_the_server_extra():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    wanted = project["dependencies"] + project["optional-dependencies"]["server"]
    names = {_normalise(re.split(r"[\[<>=!~; ]", req, maxsplit=1)[0]) for req in wanted}

    missing = names - _locked_packages()

    assert not missing


def test_the_server_lock_has_the_server_runtime():
    for name in ("fastapi", "uvicorn", "docker", "psycopg2-binary", "sqlmodel"):
        assert name in _locked_packages()


# ---------- deploy/docker-compose.yml ----------

def test_compose_builds_the_server_target_from_the_repository_root():
    build = COMPOSE["services"]["qwed-core"]["build"]
    context = (COMPOSE_PATH.parent / build["context"]).resolve()

    assert context == ROOT
    assert (context / build["dockerfile"]).is_file()
    assert build["target"] == "server"


def test_every_file_compose_mounts_exists():
    for name, service in COMPOSE["services"].items():
        for volume in service.get("volumes", []):
            source = volume.split(":", 1)[0]
            if source.startswith("."):
                assert (COMPOSE_PATH.parent / source).exists(), f"{name}: {source}"


def test_compose_requires_every_server_secret():
    env = COMPOSE["services"]["qwed-core"]["environment"]
    for name in SERVER_SECRETS:
        assert any(re.fullmatch(rf"{name}=\$\{{{name}:\?[^}}]+\}}", item) for item in env), name


def test_the_compose_healthcheck_does_not_need_curl():
    test = COMPOSE["services"]["qwed-core"]["healthcheck"]["test"]
    assert "curl" not in test
    assert any("/health" in part for part in test)


def test_the_env_example_lists_every_required_compose_variable():
    text = COMPOSE_PATH.read_text(encoding="utf-8")
    required = set(re.findall(r"\$\{([A-Z0-9_]+):\?", text))
    example = (ROOT / "deploy" / ".env.example").read_text(encoding="utf-8")
    listed = set(re.findall(r"^([A-Z0-9_]+)=", example, re.M))

    assert required <= listed
    # Postgres reads its password from the env file, not from interpolation.
    assert "POSTGRES_PASSWORD" in listed


def test_grafana_provisions_the_compose_data_sources():
    path = ROOT / "deploy" / "grafana" / "provisioning" / "datasources" / "datasources.yml"
    sources = yaml.safe_load(path.read_text(encoding="utf-8"))["datasources"]

    assert {s["url"] for s in sources} == {"http://prometheus:9090", "http://jaeger:16686"}


# ---------- Kubernetes and publishing ----------

def test_kubernetes_pins_the_first_server_image():
    deployment = yaml.safe_load((ROOT / "deploy" / "kubernetes" / "deployment.yaml").read_text(encoding="utf-8"))
    image = deployment["spec"]["template"]["spec"]["containers"][0]["image"]

    assert image == "docker.io/qwedai/qwed-verification:7.3.1"


def test_the_kubernetes_secret_has_every_server_secret():
    secret = yaml.safe_load((ROOT / "deploy" / "kubernetes" / "secret.yaml").read_text(encoding="utf-8"))
    config = yaml.safe_load((ROOT / "deploy" / "kubernetes" / "configmap.yaml").read_text(encoding="utf-8"))
    provided = set(secret["stringData"]) | set(config["data"])

    assert set(SERVER_SECRETS) <= provided


def test_shipped_secret_and_env_files_hold_no_placeholder_values():
    # A filled-in-looking placeholder passes "is it set?" checks and fails
    # only at runtime; an empty value is refused up front.
    secret = yaml.safe_load((ROOT / "deploy" / "kubernetes" / "secret.yaml").read_text(encoding="utf-8"))
    assert all(value == "" for value in secret["stringData"].values())

    example = (ROOT / "deploy" / ".env.example").read_text(encoding="utf-8")
    values = dict(re.findall(r"^([A-Z0-9_]+)=(.*)$", example, re.M))
    assert values["DATABASE_URL"] == ""
    assert not any("<" in value or "REPLACE" in value for value in values.values())


def test_docker_hub_publishes_the_server_target():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "docker-publish.yml").read_text(encoding="utf-8"))
    build = next(s for s in workflow["jobs"]["build-and-push"]["steps"] if s.get("id") == "build")

    assert build["with"]["target"] == "server"
