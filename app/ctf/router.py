import html
import logging
import time
from collections import defaultdict

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse

import json

from app.auth.router import get_current_user
from app.config import settings
from app.ctf.aider_fixer import fix_crash_with_aider, fix_validation_with_aider
from app.ctf.docker_mgr import DockerManager
from app.ctf.generator import (
    CTFChallenge,
    ExploitSpec,
    generate_ctf_from_spec,
    generate_exploit_spec,
    generate_flag,
)
from app.ctf.validator import validate_with_spec
from app.dashboard.router import get_user_api_key
from app.db import generate_public_path, get_connection

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


def get_public_url(public_path: str, container_url: str) -> str:
    """Get the public URL for a challenge.

    If CHALLENGE_PROXY_URL is set, returns the proxy URL with the public_path.
    Otherwise, returns the internal container URL (for local development).
    """
    if settings.challenge_proxy_url:
        return f"{settings.challenge_proxy_url.rstrip('/')}/{public_path}/"
    return container_url


def deploy_challenge(
    challenge: CTFChallenge, challenge_id: int, user_id: int, max_fix_attempts: int = 2
) -> tuple[str | None, str]:
    """Build and run container with agentic auto-fix on failure. Returns (url, error_message)."""
    mgr = get_docker_manager()
    if not mgr:
        return None, "Docker not available"

    app_code = challenge.app_code
    requirements = challenge.requirements
    spec = challenge.exploit_spec

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

        # Container failed - try to fix the code using Aider
        if result.logs and attempt < max_fix_attempts and spec:
            logger.info(f"Container crashed, using Aider to fix (attempt {attempt + 1})")
            api_key = get_user_api_key(user_id)
            if api_key:
                aider_result = fix_crash_with_aider(
                    app_code=app_code,
                    crash_logs=result.logs,
                    spec=spec,
                    flag=challenge.flag,
                    api_key=api_key,
                )
                if aider_result.success and aider_result.code:
                    logger.info(f"Aider fix succeeded: {aider_result.message}")
                    app_code = aider_result.code
                    mgr.cleanup_image(image_id)
                    continue
                else:
                    logger.warning(f"Aider fix failed: {aider_result.message}")
            else:
                logger.warning("No API key available for Aider fix")

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
    """Generate CTF using test-driven approach: exploit spec first, then app."""
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
    prompt = html.escape(prompt[:500])
    difficulty = difficulty if difficulty in ("easy", "medium", "hard") else "easy"
    valid_vulns = {"sqli", "xss", "cmdi", "path", "idor", "auth"}
    vuln_list = [v for v in vuln_types.split(",") if v in valid_vulns] or ["sqli"]
    vuln_type = vuln_list[0]  # Use first selected vulnerability

    msg_html = f"""
    <div class="p-3 bg-gray-700 rounded">
        <p class="text-sm text-green-400 font-medium">Generating CTF (Test-Driven)...</p>
        <p class="text-sm text-gray-300 mt-1">{prompt}</p>
        <p class="text-xs text-gray-500 mt-2">
            Difficulty: {difficulty} | Vuln: {vuln_type}
        </p>
    </div>
    """

    # Step 1: Generate exploit specification FIRST (the "test")
    logger.info(f"Generating exploit spec for {vuln_type}/{difficulty}")
    spec = generate_exploit_spec(vuln_type, difficulty, user_id)

    if not spec:
        return msg_html + error_msg(
            'Failed to generate exploit spec. <a href="/dashboard" class="underline">Set your API key</a> '
            "or try again."
        )

    # Step 2: Generate the flag
    flag = generate_flag()

    # Step 3: Generate app that matches the spec, with retry loop
    max_attempts = 3
    challenge = None
    url = None
    validation_error = None

    for attempt in range(max_attempts):
        logger.info(f"Generating app from spec (attempt {attempt + 1}/{max_attempts})")

        # Generate or fix the app
        if attempt == 0:
            challenge = generate_ctf_from_spec(spec, flag, user_id, prompt)
        elif challenge and validation_error:
            # Fix the app using Aider
            logger.info(f"Using Aider to fix validation error: {validation_error}")
            api_key = get_user_api_key(user_id)
            if api_key:
                aider_result = fix_validation_with_aider(
                    app_code=challenge.app_code,
                    validation_error=validation_error,
                    spec=spec,
                    flag=flag,
                    api_key=api_key,
                )
                if aider_result.success and aider_result.code:
                    logger.info(f"Aider fix succeeded: {aider_result.message}")
                    challenge = CTFChallenge(
                        name=challenge.name,
                        app_code=aider_result.code,
                        requirements=challenge.requirements,
                        flag=flag,
                        vuln_description=spec.exploit_description,
                        exploit_hint=f"{spec.exploit_method} {spec.exploit_path}",
                        difficulty=difficulty,
                        vuln_types=[vuln_type],
                        exploit_spec=spec,
                    )
                else:
                    # Aider fix failed, try generating fresh
                    logger.warning(f"Aider fix failed: {aider_result.message}, regenerating")
                    challenge = generate_ctf_from_spec(spec, flag, user_id, prompt)
            else:
                # No API key, regenerate from scratch
                logger.warning("No API key for Aider, regenerating from scratch")
                challenge = generate_ctf_from_spec(spec, flag, user_id, prompt)

        if not challenge:
            continue

        # Step 4: Save to database (or update)
        if attempt == 0:
            public_path = generate_public_path()
            with get_connection() as conn:
                cursor = conn.execute(
                    """INSERT INTO challenges
                       (user_id, name, public_path, vuln_type, difficulty, description, app_code, 
                        flag, status, exploit_spec)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        user_id,
                        challenge.name,
                        public_path,
                        vuln_type,
                        difficulty,
                        challenge.vuln_description,
                        challenge.app_code,
                        flag,
                        "generating",
                        serialize_spec(spec),
                    ),
                )
                challenge_id = cursor.lastrowid
        else:
            # Update the app code
            with get_connection() as conn:
                conn.execute(
                    "UPDATE challenges SET app_code = ? WHERE id = ?",
                    (challenge.app_code, challenge_id),
                )

        # Step 5: Deploy
        url, deploy_error = deploy_challenge(challenge, challenge_id, user_id)

        if deploy_error:
            validation_error = f"Deploy failed: {deploy_error}"
            logger.warning(f"Deploy failed on attempt {attempt + 1}: {deploy_error}")
            continue

        # Step 6: Validate with the spec (deterministic - no AI)
        logger.info(f"Validating with spec at {url}")
        result = validate_with_spec(url, spec, flag)

        if result.success:
            # Success! Update status and return
            with get_connection() as conn:
                conn.execute(
                    "UPDATE challenges SET status = ? WHERE id = ?",
                    ("validated", challenge_id),
                )
            logger.info(f"CTF validated successfully on attempt {attempt + 1}")
            # Return the public URL for the user
            display_url = get_public_url(public_path, url)
            return msg_html + success_msg("CTF Ready!", display_url, challenge_id)

        # Validation failed - prepare for next iteration
        validation_error = result.error
        logger.warning(f"Validation failed on attempt {attempt + 1}: {validation_error}")

        # Stop the container before retrying
        mgr = get_docker_manager()
        if mgr and url:
            with get_connection() as conn:
                row = conn.execute(
                    "SELECT container_id FROM challenges WHERE id = ?", (challenge_id,)
                ).fetchone()
                if row and row["container_id"]:
                    mgr.stop_container(row["container_id"])

    # All attempts failed
    if challenge and url:
        # Last attempt - deploy anyway but warn user
        with get_connection() as conn:
            conn.execute(
                "UPDATE challenges SET status = ? WHERE id = ?",
                ("unverified", challenge_id),
            )
        # Return the public URL for the user
        display_url = get_public_url(public_path, url)
        return msg_html + warn_msg(
            "CTF Deployed (unverified)",
            display_url,
            challenge_id,
            f"Validation failed: {validation_error}",
        )

    return msg_html + error_msg(
        f"Failed to generate working CTF after {max_attempts} attempts. "
        f"Last error: {validation_error}"
    )


def serialize_spec(spec: ExploitSpec) -> str:
    """Serialize ExploitSpec to JSON for database storage."""
    return json.dumps({
        "vuln_type": spec.vuln_type,
        "difficulty": spec.difficulty,
        "exploit_method": spec.exploit_method,
        "exploit_path": spec.exploit_path,
        "exploit_params": spec.exploit_params,
        "exploit_description": spec.exploit_description,
        "safe_method": spec.safe_method,
        "safe_path": spec.safe_path,
        "safe_params": spec.safe_params,
        "app_description": spec.app_description,
    })


def deserialize_spec(data: str) -> ExploitSpec | None:
    """Deserialize ExploitSpec from JSON."""
    try:
        d = json.loads(data)
        return ExploitSpec(
            vuln_type=d["vuln_type"],
            difficulty=d["difficulty"],
            exploit_method=d["exploit_method"],
            exploit_path=d["exploit_path"],
            exploit_params=d["exploit_params"],
            exploit_description=d["exploit_description"],
            safe_method=d["safe_method"],
            safe_path=d["safe_path"],
            safe_params=d["safe_params"],
            app_description=d["app_description"],
        )
    except (json.JSONDecodeError, KeyError):
        return None


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
