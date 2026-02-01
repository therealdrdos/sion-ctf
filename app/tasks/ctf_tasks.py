"""Celery tasks for CTF generation."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

from app.celery_app import celery_app
from app.ctf.generator import (
    CTFChallenge,
    generate_ctf_from_spec,
    generate_exploit_spec,
    generate_flag,
)
from app.ctf.router import deploy_challenge, serialize_spec
from app.ctf.validator import validate_with_spec
from app.db import append_job_log, create_job, get_job, set_job_result, update_job_status
from app.dashboard.router import get_user_api_key

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
    for attempt in range(max_attempts):
        update_job_status(job_id, "running", f"Generating app (attempt {attempt + 1})", 0.2 + attempt * 0.2)
        log(f"Generating app attempt {attempt + 1}")
        if attempt == 0:
            challenge = generate_ctf_from_spec(spec, flag, user_id, prompt)
        else:
            challenge = generate_ctf_from_spec(spec, flag, user_id, prompt)

        if not challenge:
            validation_error = "Failed to generate app"
            continue

        # Deploy
        url, deploy_error = deploy_challenge(challenge, challenge_id=job_id, user_id=user_id)
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
            # Persist artifacts once on success
            job_dir, expires_at = _persist_artifacts(
                job_id,
                app_code=challenge.app_code,
                requirements=challenge.requirements,
                spec=spec,
                flag=flag,
                url=url,
                challenge_name=challenge.name,
            )
            log(f"Artifacts persisted. Expires at {expires_at}")

            set_job_result(
                job_id,
                "success",
                "CTF ready",
                {
                    "challenge_name": challenge.name,
                    "url": url,
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
    failure_result = {
        "error": validation_error or "Validation failed",
        "attempts": max_attempts,
    }
    if last_app_code and last_requirements:
        job_dir, expires_at = _persist_artifacts(
            job_id,
            app_code=last_app_code,
            requirements=last_requirements,
            spec=spec,
            flag=flag,
            url=last_url,
            challenge_name=last_challenge_name,
        )
        log(f"Artifacts persisted (failure). Expires at {expires_at}")
        failure_result["download_path"] = str(job_dir)
        failure_result["expires_at"] = expires_at
        if last_url:
            failure_result["url"] = last_url
        if last_challenge_name:
            failure_result["challenge_name"] = last_challenge_name
    set_job_result(job_id, "failed", validation_error or "Failed to generate working CTF", failure_result)
    log("Job failed")
    return
