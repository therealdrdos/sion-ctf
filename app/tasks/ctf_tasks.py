"""Celery tasks for CTF generation."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

from app.celery_app import celery_app
from app.ctf.generator import (
    CTFChallenge,
    generate_exploit_spec,
    generate_flag,
    validate_code,
    TEMPLATE_PROMPT,
)
from app.ctf.templates import get_template_for_vuln
from app.ctf.router import deploy_challenge, get_public_url, serialize_spec
from app.ctf.validator import validate_with_spec
from app.db import (
    append_job_log,
    create_job,
    generate_public_path,
    get_connection,
    get_job,
    set_job_result,
    update_job_status,
)
from app.dashboard.router import get_user_api_key
from app.ctf.aider_cli import run_aider_cli

logger = logging.getLogger(__name__)

# Job artifact storage
JOB_ROOT = Path("data/tmp/jobs")
JOB_TTL_SECONDS = 1800  # 30 minutes


def _job_dir(job_id: int) -> Path:
    return JOB_ROOT / str(job_id)


def _cleanup_expired_jobs():
    if not JOB_ROOT.exists():
        return
    now = int(__import__("time").time())
    for child in JOB_ROOT.iterdir():
        if not child.is_dir():
            continue
        meta = child / "metadata.json"
        try:
            data = json.loads(meta.read_text()) if meta.exists() else {}
            exp = data.get("expires_at", 0)
            if exp and now >= exp:
                import shutil

                shutil.rmtree(child, ignore_errors=True)
        except Exception:
            import shutil

            shutil.rmtree(child, ignore_errors=True)


def _persist_artifacts(
    job_id: int,
    *,
    app_code: str,
    requirements: str,
    spec,
    flag: str,
    url: str | None,
    challenge_name: str | None,
) -> tuple[Path, int]:
    """Write artifacts for a job and return (job_dir, expires_at)."""
    job_dir = _job_dir(job_id)
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "app.py").write_text(app_code)
    (job_dir / "requirements.txt").write_text(requirements)
    (job_dir / "solution.txt").write_text(
        f"Exploit: {spec.exploit_method} {spec.exploit_path} with {spec.exploit_params}\n"
    )
    (job_dir / "spec.json").write_text(serialize_spec(spec))

    # Copy verify script if present
    root = Path(__file__).resolve().parents[2]
    verify_path = root / "verify_challenge.py"
    if verify_path.exists():
        (job_dir / "verify_challenge.py").write_text(verify_path.read_text())

    expires_at = int(__import__("time").time()) + JOB_TTL_SECONDS
    meta = {
        "job_id": job_id,
        "url": url,
        "flag": flag,
        "challenge_name": challenge_name,
        "expires_at": expires_at,
    }
    (job_dir / "metadata.json").write_text(json.dumps(meta))
    return job_dir, expires_at


def _build_with_aider(spec, flag: str, user_id: int, prompt: str) -> CTFChallenge | None:
    """Use Aider CLI to add vulnerable code to a template based on spec."""
    api_key = get_user_api_key(user_id)
    if not api_key:
        return None

    template_name, template_code = get_template_for_vuln(spec.vuln_type)
    template_code = template_code.replace('FLAG = "FLAG{placeholder}"', f'FLAG = "{flag}"')

    # Instruction derived from TEMPLATE_PROMPT + spec
    instruction = (
        "You will edit app.py (a Flask template) to add the vulnerable endpoint(s) that satisfy this exploit spec.\n"
        f"Template type: {template_name}\n\n"
        f"{TEMPLATE_PROMPT}\n\n"
        "Exploit that MUST return the flag:\n"
        f"- Method: {spec.exploit_method}\n"
        f"- Path: {spec.exploit_path}\n"
        f"- Params: {json.dumps(spec.exploit_params)}\n"
        f"- Description: {spec.exploit_description}\n\n"
        "Safe request that must NOT return the flag:\n"
        f"- Method: {spec.safe_method}\n"
        f"- Path: {spec.safe_path}\n"
        f"- Params: {json.dumps(spec.safe_params)}\n\n"
        f"User request/theme: {prompt}\n"
        "Do NOT remove the FLAG. Keep /health working. Use modern Flask.\n"
        "Edit app.py directly; do not rename files. Keep code minimal.\n"
    )

    spec_json = json.dumps(
        {
            "flag": flag,
            "exploit_method": spec.exploit_method,
            "exploit_path": spec.exploit_path,
            "exploit_params": spec.exploit_params,
            "safe_method": spec.safe_method,
            "safe_path": spec.safe_path,
            "safe_params": spec.safe_params,
        }
    )

    docs_path = Path("ctf_framework_docs.md")
    docs_arg = str(docs_path) if docs_path.exists() else None

    result = run_aider_cli(
        app_code=template_code,
        requirements="flask",
        instruction=instruction,
        api_key=api_key,
        docs_path=docs_arg,
        extra_files={"spec.json": spec_json},
    )
    if not result.success or not result.app_code:
        return None

    app_code = result.app_code
    if flag not in app_code:
        return None
    if not validate_code(app_code):
        return None

    return CTFChallenge(
        name=f"{spec.vuln_type} challenge",
        app_code=app_code,
        requirements=result.requirements or "flask",
        flag=flag,
        vuln_description=spec.exploit_description,
        exploit_hint=f"{spec.exploit_method} {spec.exploit_path}",
        difficulty=spec.difficulty,
        vuln_types=[spec.vuln_type],
        exploit_spec=spec,
    )


@celery_app.task(name="app.tasks.ctf_tasks.run_ctf_job")
def run_ctf_job(job_id: int, payload: Dict[str, Any]) -> None:
    """
    Run the CTF generation flow in a background worker.

    payload expects:
        user_id: int
        prompt: str
        difficulty: str
        vuln_type: str
    """
    job = get_job(job_id)
    if not job:
        return

    user_id = payload["user_id"]
    prompt = payload.get("prompt", "")
    difficulty = payload.get("difficulty", "easy")
    vuln_type = payload.get("vuln_type", "sqli")

    _cleanup_expired_jobs()

    def log(line: str):
        append_job_log(job_id, line)
        logger.info("[JOB %s] %s", job_id, line)

    update_job_status(job_id, "running", "Generating exploit spec", 0.05)
    log("Starting job")

    # Step 1: Generate exploit spec
    spec = generate_exploit_spec(vuln_type, difficulty, user_id)
    if not spec:
        set_job_result(job_id, "failed", "Failed to generate exploit spec")
        return

    # Step 2: Generate flag
    flag = generate_flag()

    # Step 3: Generate app from spec with retries
    max_attempts = 5
    challenge: CTFChallenge | None = None
    validation_error = None
    last_app_code: str | None = None
    last_requirements: str | None = None
    last_url: str | None = None
    last_challenge_name: str | None = None
    challenge_id: int | None = None
    public_path: str | None = None

    for attempt in range(max_attempts):
        update_job_status(job_id, "running", f"Generating app (attempt {attempt + 1})", 0.2 + attempt * 0.2)
        log(f"Generating app attempt {attempt + 1}")
        challenge = _build_with_aider(spec, flag, user_id, prompt)

        if not challenge:
            validation_error = "Failed to generate app"
            continue

        # Create or update challenge in database
        if challenge_id is None:
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
            log(f"Created challenge {challenge_id} with public_path {public_path}")
        else:
            # Update the app code
            with get_connection() as conn:
                conn.execute(
                    "UPDATE challenges SET app_code = ? WHERE id = ?",
                    (challenge.app_code, challenge_id),
                )

        # Deploy
        url, deploy_error = deploy_challenge(challenge, challenge_id=challenge_id, user_id=user_id)
        if deploy_error:
            validation_error = f"Deploy failed: {deploy_error}"
            log(validation_error)
            continue

        # Validate
        update_job_status(job_id, "running", "Validating app", 0.8)
        result = validate_with_spec(url, spec, flag)
        # Track last attempt artifacts to persist at the end
        last_app_code = challenge.app_code
        last_requirements = challenge.requirements
        last_url = url
        last_challenge_name = challenge.name

        if result.success:
            # Update challenge status
            with get_connection() as conn:
                conn.execute(
                    "UPDATE challenges SET status = ? WHERE id = ?",
                    ("validated", challenge_id),
                )

            # Get the public URL for display
            display_url = get_public_url(public_path, url) if public_path else url

            # Persist artifacts once on success
            job_dir, expires_at = _persist_artifacts(
                job_id,
                app_code=challenge.app_code,
                requirements=challenge.requirements,
                spec=spec,
                flag=flag,
                url=display_url,
                challenge_name=challenge.name,
            )
            log(f"Artifacts persisted. Expires at {expires_at}")

            set_job_result(
                job_id,
                "success",
                "CTF ready",
                {
                    "challenge_id": challenge_id,
                    "challenge_name": challenge.name,
                    "url": display_url,
                    "flag": flag,
                    "exploit_spec": serialize_spec(spec),
                    "download_path": str(job_dir),
                    "expires_at": expires_at,
                },
            )
            log("Job succeeded")
            return

        # If validation failed, keep retrying
        validation_error = result.error or "Validation failed"
        log(validation_error)

    # All attempts failed
    log(f"Failed to generate working CTF after {max_attempts} attempts. Last error: {validation_error}")

    # Update challenge status to failed
    if challenge_id:
        with get_connection() as conn:
            conn.execute(
                "UPDATE challenges SET status = ? WHERE id = ?",
                ("failed", challenge_id),
            )

    # Get display URL for failure result
    display_url = get_public_url(public_path, last_url) if public_path and last_url else last_url

    failure_result = {
        "error": validation_error or "Validation failed",
        "attempts": max_attempts,
    }
    if challenge_id:
        failure_result["challenge_id"] = challenge_id
    if last_app_code and last_requirements:
        job_dir, expires_at = _persist_artifacts(
            job_id,
            app_code=last_app_code,
            requirements=last_requirements,
            spec=spec,
            flag=flag,
            url=display_url,
            challenge_name=last_challenge_name,
        )
        log(f"Artifacts persisted (failure). Expires at {expires_at}")
        failure_result["download_path"] = str(job_dir)
        failure_result["expires_at"] = expires_at
        if display_url:
            failure_result["url"] = display_url
        if last_challenge_name:
            failure_result["challenge_name"] = last_challenge_name
    set_job_result(job_id, "failed", validation_error or "Failed to generate working CTF", failure_result)
    log("Job failed")
    return
