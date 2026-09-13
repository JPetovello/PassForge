from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = (REPOSITORY_ROOT / "Dockerfile").read_text(encoding="utf-8")
GUNICORN_CONFIG = (
    REPOSITORY_ROOT / "gunicorn.conf.py"
).read_text(encoding="utf-8")


def test_container_preserves_non_root_runtime_identity():
    assert "USER 99:100" in DOCKERFILE
    assert "USER root" not in DOCKERFILE


def test_application_tree_is_not_owned_or_writable_by_runtime_user():
    assert "COPY --chown=0:0 requirements.lock ." in DOCKERFILE
    assert "COPY --chown=0:0 . ." in DOCKERFILE
    assert "chmod -R go-w /app" in DOCKERFILE
    assert "chown -R 99:100 /app" not in DOCKERFILE
    assert "chmod 777" not in DOCKERFILE


def test_container_has_no_unneeded_writable_application_data_directory():
    assert "/app/data" not in DOCKERFILE


def test_python_runtime_writes_are_confined_to_temporary_storage():
    assert "HOME=/tmp" in DOCKERFILE
    assert "TMPDIR=/tmp" in DOCKERFILE
    assert "PYTHONDONTWRITEBYTECODE=1" in DOCKERFILE


def test_unused_gunicorn_control_socket_is_disabled():
    assert "control_socket_disable = True" in GUNICORN_CONFIG
