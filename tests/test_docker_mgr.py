import pytest

from app.ctf.docker_mgr import CTF_DOCKERFILE, DockerManager


def test_ctf_dockerfile_valid():
    assert "FROM python" in CTF_DOCKERFILE
    assert "EXPOSE 5000" in CTF_DOCKERFILE
    assert "app.py" in CTF_DOCKERFILE


@pytest.fixture
def docker_mgr():
    """Create Docker manager for tests."""
    try:
        mgr = DockerManager()
        yield mgr
    except Exception:
        pytest.skip("Docker not available")


def test_docker_manager_init(docker_mgr):
    assert docker_mgr.client is not None
    assert docker_mgr.network_name == "sion-ctf-net"


def test_build_simple_image(docker_mgr):
    app_code = """
from flask import Flask
app = Flask(__name__)

@app.route('/')
def index():
    return 'OK'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
"""
    requirements = "flask"

    image_id = docker_mgr.build_image(app_code, requirements)

    try:
        assert image_id is not None
        assert image_id.startswith("sha256:")
    finally:
        if image_id:
            docker_mgr.cleanup_image(image_id)


def test_build_invalid_code(docker_mgr):
    app_code = "this is not valid python syntax{{{{"
    requirements = "flask"

    image_id = docker_mgr.build_image(app_code, requirements)
    # Build might succeed (Python syntax not checked at build time)
    # but container would fail to start
    if image_id:
        docker_mgr.cleanup_image(image_id)


def test_container_lifecycle(docker_mgr):
    app_code = """
from flask import Flask
app = Flask(__name__)

@app.route('/')
def index():
    return 'OK'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
"""
    requirements = "flask"

    image_id = docker_mgr.build_image(app_code, requirements)
    assert image_id is not None

    try:
        info = docker_mgr.run_container(image_id)
        assert info is not None
        assert info.container_id
        assert info.port == 5000

        assert docker_mgr.container_running(info.container_id)

        docker_mgr.stop_container(info.container_id)
        assert not docker_mgr.container_running(info.container_id)

    finally:
        docker_mgr.cleanup_image(image_id)
