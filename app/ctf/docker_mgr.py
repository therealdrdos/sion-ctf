import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import docker
from docker.errors import BuildError, ContainerError, ImageNotFound

CTF_DOCKERFILE = """FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 5000
CMD ["python", "app.py"]
"""


@dataclass
class ContainerInfo:
    container_id: str
    image_id: str
    ip_address: str
    port: int
    url: str


def _get_docker_client():
    """Try multiple Docker socket locations (macOS Docker Desktop compatibility)."""
    import os

    # Try default first (respects DOCKER_HOST env var)
    try:
        client = docker.from_env()
        client.ping()
        return client
    except Exception:
        pass

    # macOS Docker socket locations (Colima, Docker Desktop, etc.)
    home = os.path.expanduser("~")
    socket_paths = [
        f"unix://{home}/.config/colima/default/docker.sock",
        f"unix://{home}/.colima/default/docker.sock",
        f"unix://{home}/.docker/run/docker.sock",
        "unix:///var/run/docker.sock",
        f"unix://{home}/Library/Containers/com.docker.docker/Data/docker.sock",
    ]

    for sock in socket_paths:
        try:
            client = docker.DockerClient(base_url=sock)
            client.ping()
            return client
        except Exception:
            continue

    raise docker.errors.DockerException("Could not connect to Docker daemon")


class DockerManager:
    def __init__(self):
        self.client = _get_docker_client()
        self.network_name = "sion-ctf-net"
        self._ensure_network()

    def _ensure_network(self):
        """Create isolated network for CTF containers if it doesn't exist."""
        try:
            self.client.networks.get(self.network_name)
        except docker.errors.NotFound:
            self.client.networks.create(
                self.network_name,
                driver="bridge",
                internal=False,
            )

    def build_image(self, app_code: str, requirements: str) -> str | None:
        """Build Docker image from generated code. Returns image ID or None."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            (tmppath / "Dockerfile").write_text(CTF_DOCKERFILE)
            (tmppath / "app.py").write_text(app_code)
            (tmppath / "requirements.txt").write_text(requirements)

            try:
                image, _ = self.client.images.build(
                    path=tmpdir,
                    rm=True,
                    forcerm=True,
                )
                return image.id
            except BuildError:
                return None

    def run_container(
        self,
        image_id: str,
        name_prefix: str = "ctf",
        memory_limit: str = "512m",
        cpu_quota: int = 50000,
    ) -> ContainerInfo | None:
        """Run container and return connection info."""
        try:
            container = self.client.containers.run(
                image_id,
                detach=True,
                name=f"{name_prefix}-{int(time.time())}",
                ports={"5000/tcp": None},
                mem_limit=memory_limit,
                cpu_quota=cpu_quota,
                auto_remove=False,
            )

            # Wait for container to be ready
            for _ in range(10):
                container.reload()
                if container.status == "running":
                    break
                time.sleep(0.5)

            # Wait for Flask to start
            time.sleep(2)

            # Get the published host port
            container.reload()
            ports = container.attrs.get("NetworkSettings", {}).get("Ports", {})
            if "5000/tcp" in ports and ports["5000/tcp"]:
                host_port = ports["5000/tcp"][0]["HostPort"]
                return ContainerInfo(
                    container_id=container.id,
                    image_id=image_id,
                    ip_address="127.0.0.1",
                    port=int(host_port),
                    url=f"http://127.0.0.1:{host_port}",
                )

            return None

        except (ContainerError, ImageNotFound):
            return None

    def stop_container(self, container_id: str, timeout: int = 5):
        """Stop and remove a container."""
        try:
            container = self.client.containers.get(container_id)
            container.stop(timeout=timeout)
            container.remove(force=True)
        except docker.errors.NotFound:
            pass

    def cleanup_image(self, image_id: str):
        """Remove an image."""
        try:
            self.client.images.remove(image_id, force=True)
        except ImageNotFound:
            pass

    def get_container_logs(self, container_id: str, tail: int = 100) -> str:
        """Get container logs for debugging."""
        try:
            container = self.client.containers.get(container_id)
            return container.logs(tail=tail).decode()
        except docker.errors.NotFound:
            return ""

    def container_running(self, container_id: str) -> bool:
        """Check if container is still running."""
        try:
            container = self.client.containers.get(container_id)
            return container.status == "running"
        except docker.errors.NotFound:
            return False

    def cleanup_all_ctf_containers(self):
        """Remove all CTF containers (for cleanup on shutdown)."""
        for container in self.client.containers.list(all=True):
            if container.name.startswith("ctf-"):
                try:
                    container.stop(timeout=2)
                    container.remove(force=True)
                except Exception:
                    pass
