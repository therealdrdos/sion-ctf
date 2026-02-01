"""Celery tasks for CTF generation."""

from __future__ import annotations

import json
import logging
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
        if result.success:
            # Success
            set_job_result(
                job_id,
                "success",
                "CTF ready",
                {
                    "challenge_name": challenge.name,
                    "url": url,
                    "flag": flag,
                    "exploit_spec": serialize_spec(spec),
                },
            )
            log("CTF validated successfully")
            return

        validation_error = result.error or "Validation failed"
        log(validation_error)

    # If here, failed all attempts
    set_job_result(job_id, "failed", validation_error or "Failed to generate working CTF")
    log("Job failed")
