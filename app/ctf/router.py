import html
import logging
import time
from collections import defaultdict

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse

from app.auth.router import get_current_user
from app.ctf.docker_mgr import DockerManager
from app.ctf.generator import CTFChallenge
from app.ctf.generator import generate_ctf as gen_ctf
from app.ctf.validator import validate_challenge
from app.db import get_connection

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ctf", tags=["ctf"])

# Simple in-memory rate limiting
_rate_limit: dict[int, float] = defaultdict(float)
RATE_LIMIT_SECONDS = 30

# Global docker manager instance
_docker_mgr: DockerManager | None = None


def get_docker_manager() -> DockerManager | None:
    global _docker_mgr
    if _docker_mgr is None:
        try:
            _docker_mgr = DockerManager()
        except Exception as e:
            logger.warning(f"Docker not available: {e}")
            return None
    return _docker_mgr


def deploy_challenge(challenge: CTFChallenge, challenge_id: int) -> tuple[str | None, str]:
    """Build and run container. Returns (url, error_message)."""
    mgr = get_docker_manager()
    if not mgr:
        return None, "Docker not available"

    image_id = mgr.build_image(challenge.app_code, challenge.requirements)
    if not image_id:
        return None, "Failed to build container image"

    info = mgr.run_container(image_id, name_prefix=f"ctf-{challenge_id}")
    if not info:
        mgr.cleanup_image(image_id)
        return None, "Failed to start container"

    # Update database with container info
    with get_connection() as conn:
        conn.execute(
            "UPDATE challenges SET container_id = ?, container_url = ?, status = ? WHERE id = ?",
            (info.container_id, info.url, "running", challenge_id),
        )

    return info.url, ""


@router.post("/generate", response_class=HTMLResponse)
async def generate_ctf(
    request: Request,
    prompt: str = Form(...),
    difficulty: str = Form("easy"),
    vuln_types: str = Form("sqli"),
):
    """Generate, validate, and deploy a CTF challenge."""
    user = get_current_user(request)
    if not user:
        return '<div class="p-3 bg-red-900 rounded text-red-200">Not authenticated</div>'

    # Rate limiting
    user_id = user["id"]
    now = time.time()
    if now - _rate_limit[user_id] < RATE_LIMIT_SECONDS:
        wait = int(RATE_LIMIT_SECONDS - (now - _rate_limit[user_id]))
        return error_msg(f"Please wait {wait}s before generating another challenge.")
    _rate_limit[user_id] = now

    # Sanitize inputs
    prompt = html.escape(prompt[:500])  # Limit length and escape HTML
    difficulty = difficulty if difficulty in ("easy", "medium", "hard") else "easy"
    valid_vulns = {"sqli", "xss", "cmdi", "path", "idor", "auth"}
    vuln_list = [v for v in vuln_types.split(",") if v in valid_vulns] or ["sqli"]

    # Step 1: Generate
    msg_html = f"""
    <div class="p-3 bg-gray-700 rounded">
        <p class="text-sm text-green-400 font-medium">Generating CTF...</p>
        <p class="text-sm text-gray-300 mt-1">{prompt}</p>
        <p class="text-xs text-gray-500 mt-2">
            Difficulty: {difficulty} | Vulns: {", ".join(vuln_list)}
        </p>
    </div>
    """

    challenge = gen_ctf(prompt, difficulty, vuln_list)

    if not challenge:
        return msg_html + error_msg("Failed to generate CTF. Check API key or try again.")

    # Step 2: Save to database
    with get_connection() as conn:
        cursor = conn.execute(
            """INSERT INTO challenges
               (user_id, vuln_type, difficulty, description, app_code, flag, status)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                user["id"],
                ",".join(challenge.vuln_types),
                challenge.difficulty,
                challenge.vuln_description,
                challenge.app_code,
                challenge.flag,
                "generated",
            ),
        )
        challenge_id = cursor.lastrowid

    # Step 3: Deploy
    url, deploy_error = deploy_challenge(challenge, challenge_id)

    if deploy_error:
        return msg_html + info_msg(
            f"CTF generated (ID: {challenge_id})",
            challenge.vuln_description,
            f"Deployment: {deploy_error}. Tutorial still available.",
            challenge_id,
        )

    # Step 4: Validate (optional, skip if it fails)
    try:
        valid, _, _ = validate_challenge(
            challenge.app_code,
            challenge.flag,
            url,
            vuln_list,
            max_retries=1,
        )
        if valid:
            with get_connection() as conn:
                conn.execute(
                    "UPDATE challenges SET status = ? WHERE id = ?",
                    ("validated", challenge_id),
                )
    except Exception:
        pass  # Validation is optional

    return msg_html + success_msg(
        "CTF Ready!",
        challenge.vuln_description,
        url,
        challenge_id,
        challenge.exploit_hint,
    )


@router.post("/stop/{challenge_id}", response_class=HTMLResponse)
async def stop_challenge(request: Request, challenge_id: int):
    """Stop a running challenge container."""
    user = get_current_user(request)
    if not user:
        return error_msg("Not authenticated")

    with get_connection() as conn:
        challenge = conn.execute(
            "SELECT * FROM challenges WHERE id = ? AND user_id = ?",
            (challenge_id, user["id"]),
        ).fetchone()

    if not challenge:
        return error_msg("Challenge not found")

    container_id = challenge["container_id"]
    if container_id:
        mgr = get_docker_manager()
        if mgr:
            mgr.stop_container(container_id)

        with get_connection() as conn:
            conn.execute(
                "UPDATE challenges SET status = ?, container_id = NULL WHERE id = ?",
                ("stopped", challenge_id),
            )

    return '<div class="p-3 bg-gray-700 rounded text-gray-300">Challenge stopped.</div>'


def error_msg(msg: str) -> str:
    return f'<div class="p-3 bg-red-900 rounded text-red-200 mt-2">{msg}</div>'


def info_msg(title: str, desc: str, note: str, challenge_id: int) -> str:
    return f"""
    <div class="p-3 bg-yellow-900 rounded text-yellow-200 mt-2">
        <p class="font-medium">{title}</p>
        <p class="text-sm mt-1">{desc}</p>
        <p class="text-sm text-yellow-400 mt-2">{note}</p>
        <a href="/tutorial/{challenge_id}"
           class="inline-block mt-2 px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-sm">
            View Tutorial
        </a>
    </div>
    """


def success_msg(title: str, desc: str, url: str, challenge_id: int, hint: str) -> str:
    return f"""
    <div class="p-3 bg-green-900 rounded text-green-200 mt-2">
        <p class="font-medium">{title}</p>
        <p class="text-sm mt-1">{desc}</p>
        <p class="text-xs text-gray-400 mt-2">Hint: {hint}</p>
        <div class="mt-3 flex gap-2 flex-wrap">
            <a href="{url}" target="_blank"
               class="px-3 py-1 bg-blue-600 hover:bg-blue-700 rounded text-sm">
                Open Challenge
            </a>
            <a href="/tutorial/{challenge_id}"
               class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-sm">
                View Tutorial
            </a>
            <button hx-post="/ctf/stop/{challenge_id}" hx-swap="outerHTML"
                    class="px-3 py-1 bg-red-700 hover:bg-red-600 rounded text-sm">
                Stop
            </button>
        </div>
    </div>
    <script>
        showChallenge("{url}", "{desc}", {challenge_id});
    </script>
    """
