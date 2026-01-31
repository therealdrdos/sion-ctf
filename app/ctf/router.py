import html
import logging
import time
from collections import defaultdict

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse

from app.auth.router import get_current_user
from app.ctf.docker_mgr import DockerManager
from app.ctf.generator import CTFChallenge, fix_code
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


def deploy_challenge(
    challenge: CTFChallenge, challenge_id: int, user_id: int, max_fix_attempts: int = 2
) -> tuple[str | None, str]:
    """Build and run container with auto-fix on failure. Returns (url, error_message)."""
    mgr = get_docker_manager()
    if not mgr:
        return None, "Docker not available"

    app_code = challenge.app_code
    requirements = challenge.requirements

    for attempt in range(max_fix_attempts + 1):
        image_id = mgr.build_image(app_code, requirements)
        if not image_id:
            return None, "Failed to build container image"

        result = mgr.run_container(image_id, name_prefix=f"ctf-{challenge_id}")

        if result.success and result.info:
            # Update database with container info
            with get_connection() as conn:
                conn.execute(
                    "UPDATE challenges SET container_id = ?, container_url = ?, "
                    "app_code = ?, status = ? WHERE id = ?",
                    (result.info.container_id, result.info.url, app_code, "running", challenge_id),
                )
            return result.info.url, ""

        # Container failed - try to fix the code
        if result.logs and attempt < max_fix_attempts:
            logger.info(f"Container crashed, attempting fix (attempt {attempt + 1})")
            fixed_code = fix_code(app_code, result.logs, user_id)
            if fixed_code:
                # Verify fixed code still contains the flag
                if challenge.flag in fixed_code:
                    app_code = fixed_code
                    mgr.cleanup_image(image_id)
                    continue
                else:
                    logger.warning("Fixed code missing flag, skipping fix")

        # No fix possible or last attempt
        mgr.cleanup_image(image_id)
        error_msg = result.error or "Failed to start container"
        if result.logs:
            # Include first line of error in message
            first_error = result.logs.strip().split("\n")[-1][:100]
            error_msg = f"{error_msg}: {first_error}"
        return None, error_msg

    return None, "Failed to start container after fix attempts"


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

    challenge = gen_ctf(prompt, difficulty, vuln_list, user_id)

    if not challenge:
        return msg_html + error_msg(
            'Failed to generate CTF. <a href="/dashboard" class="underline">Set your API key</a> '
            "in the Dashboard or try again."
        )

    # Step 2: Save to database
    with get_connection() as conn:
        cursor = conn.execute(
            """INSERT INTO challenges
               (user_id, name, vuln_type, difficulty, description, app_code, flag, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user["id"],
                challenge.name,
                ",".join(challenge.vuln_types),
                challenge.difficulty,
                challenge.vuln_description,
                challenge.app_code,
                challenge.flag,
                "generated",
            ),
        )
        challenge_id = cursor.lastrowid

    # Step 3: Deploy (with auto-fix on crash)
    url, deploy_error = deploy_challenge(challenge, challenge_id, user_id)

    if deploy_error:
        return msg_html + info_msg(
            f"CTF generated (ID: {challenge_id})",
            challenge.vuln_description,
            f"Deployment: {deploy_error}. Tutorial still available.",
            challenge_id,
        )

    # Step 4: Validate that the flag is actually extractable
    validated = False
    try:
        valid, solution, err = validate_challenge(
            app_code=challenge.app_code,
            expected_flag=challenge.flag,
            target_url=url,
            vuln_types=vuln_list,
            vuln_description=challenge.vuln_description,
            exploit_hint=challenge.exploit_hint,
            exploit_payload=challenge.exploit_payload,
            user_id=user_id,
            max_retries=1,
        )
        if valid:
            validated = True
            with get_connection() as conn:
                conn.execute(
                    "UPDATE challenges SET status = ? WHERE id = ?",
                    ("validated", challenge_id),
                )
    except Exception as e:
        logger.warning(f"Validation error: {e}")

    if validated:
        return msg_html + success_msg("CTF Ready!", url, challenge_id)

    # Validation failed - warn user but still allow playing
    return msg_html + warn_msg(
        "CTF Deployed (unverified)",
        url,
        challenge_id,
        "Flag extraction could not be verified. Challenge may be harder than intended.",
    )


@router.post("/check/{challenge_id}", response_class=HTMLResponse)
async def check_flag(request: Request, challenge_id: int, flag: str = Form(...)):
    """Check if submitted flag is correct."""
    user = get_current_user(request)
    if not user:
        return error_msg("Not authenticated")

    with get_connection() as conn:
        challenge = conn.execute(
            "SELECT flag FROM challenges WHERE id = ? AND user_id = ?",
            (challenge_id, user["id"]),
        ).fetchone()

    if not challenge:
        return error_msg("Challenge not found")

    if flag.strip() == challenge["flag"]:
        return '<div class="p-2 bg-green-900 rounded text-green-200 text-sm mt-2">Correct!</div>'
    return '<div class="p-2 bg-red-900 rounded text-red-200 text-sm mt-2">Wrong flag</div>'


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


@router.delete("/challenge/{challenge_id}", response_class=HTMLResponse)
async def delete_challenge(request: Request, challenge_id: int):
    """Delete a challenge."""
    user = get_current_user(request)
    if not user:
        return error_msg("Not authenticated")

    with get_connection() as conn:
        challenge = conn.execute(
            "SELECT container_id FROM challenges WHERE id = ? AND user_id = ?",
            (challenge_id, user["id"]),
        ).fetchone()

        if not challenge:
            return error_msg("Challenge not found")

        # Stop container if running
        if challenge["container_id"]:
            mgr = get_docker_manager()
            if mgr:
                mgr.stop_container(challenge["container_id"])

        conn.execute("DELETE FROM challenges WHERE id = ?", (challenge_id,))

    return ""


@router.delete("/challenges", response_class=HTMLResponse)
async def delete_all_challenges(request: Request):
    """Delete all challenges for current user."""
    user = get_current_user(request)
    if not user:
        return error_msg("Not authenticated")

    with get_connection() as conn:
        challenges = conn.execute(
            "SELECT container_id FROM challenges WHERE user_id = ? AND container_id IS NOT NULL",
            (user["id"],),
        ).fetchall()

        # Stop all containers
        mgr = get_docker_manager()
        if mgr:
            for c in challenges:
                mgr.stop_container(c["container_id"])

        conn.execute("DELETE FROM challenges WHERE user_id = ?", (user["id"],))

    return ""


def error_msg(msg: str) -> str:
    return f'<div class="p-3 bg-red-900 rounded text-red-200 mt-2">{msg}</div>'


def info_msg(title: str, desc: str, note: str, challenge_id: int) -> str:
    return f"""
    <div class="p-3 bg-yellow-900 rounded text-yellow-200 mt-2">
        <p class="font-medium">{title}</p>
        <p class="text-sm mt-1">{desc}</p>
        <p class="text-sm text-yellow-400 mt-2">{note}</p>
        <a href="/tutorial/{challenge_id}" target="_blank"
           class="inline-block mt-2 px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-sm">
            View Tutorial
        </a>
    </div>
    """


def warn_msg(title: str, url: str, challenge_id: int, warning: str) -> str:
    return f"""
    <div class="p-3 bg-yellow-900 rounded text-yellow-200 mt-2">
        <p class="font-medium">{title}</p>
        <p class="text-xs text-yellow-400 mt-1">{warning}</p>
        <div class="mt-3 flex gap-2 flex-wrap">
            <a href="{url}" target="_blank"
               class="px-3 py-1 bg-blue-600 hover:bg-blue-700 rounded text-sm">
                Open Challenge
            </a>
            <a href="/tutorial/{challenge_id}" target="_blank"
               class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-sm">
                View Tutorial
            </a>
            <button hx-post="/ctf/stop/{challenge_id}" hx-swap="outerHTML"
                    class="px-3 py-1 bg-red-700 hover:bg-red-600 rounded text-sm">
                Stop
            </button>
        </div>
        <form hx-post="/ctf/check/{challenge_id}" hx-target="#flag-result-{challenge_id}" hx-swap="innerHTML" class="mt-3">
            <div class="flex gap-2">
                <input type="text" name="flag" placeholder="FLAG{{...}}"
                       class="flex-1 px-3 py-1 bg-gray-800 border border-gray-600 rounded text-sm focus:border-green-500 focus:outline-none">
                <button type="submit" class="px-3 py-1 bg-green-700 hover:bg-green-600 rounded text-sm">Check</button>
            </div>
            <div id="flag-result-{challenge_id}"></div>
        </form>
    </div>
    <script>
        showChallenge("{url}", "{title}", {challenge_id});
    </script>
    """


def success_msg(title: str, url: str, challenge_id: int) -> str:
    return f"""
    <div class="p-3 bg-green-900 rounded text-green-200 mt-2">
        <p class="font-medium">{title}</p>
        <p class="text-sm text-gray-400 mt-1">Find the flag. Need help? Check the tutorial.</p>
        <div class="mt-3 flex gap-2 flex-wrap">
            <a href="{url}" target="_blank"
               class="px-3 py-1 bg-blue-600 hover:bg-blue-700 rounded text-sm">
                Open Challenge
            </a>
            <a href="/tutorial/{challenge_id}" target="_blank"
               class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-sm">
                View Tutorial
            </a>
            <button hx-post="/ctf/stop/{challenge_id}" hx-swap="outerHTML"
                    class="px-3 py-1 bg-red-700 hover:bg-red-600 rounded text-sm">
                Stop
            </button>
        </div>
        <form hx-post="/ctf/check/{challenge_id}" hx-target="#flag-result-{challenge_id}" hx-swap="innerHTML" class="mt-3">
            <div class="flex gap-2">
                <input type="text" name="flag" placeholder="FLAG{{...}}"
                       class="flex-1 px-3 py-1 bg-gray-800 border border-gray-600 rounded text-sm focus:border-green-500 focus:outline-none">
                <button type="submit" class="px-3 py-1 bg-green-700 hover:bg-green-600 rounded text-sm">Check</button>
            </div>
            <div id="flag-result-{challenge_id}"></div>
        </form>
    </div>
    <script>
        showChallenge("{url}", "{title}", {challenge_id});
    </script>
    """
