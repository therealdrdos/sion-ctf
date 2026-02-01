from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth.router import get_current_user
from app.tasks.ctf_tasks import run_ctf_job
from app.db import create_job, get_job

router = APIRouter(prefix="/api/jobs", tags=["jobs"])
logger = logging.getLogger(__name__)


class JobRequest(BaseModel):
    prompt: str
    difficulty: str = "easy"
    vuln_type: str = "sqli"


@router.post("", status_code=202)
async def enqueue_job(payload: JobRequest, user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    job_id = create_job(
        user_id=user["id"],
        payload={
            "prompt": payload.prompt,
            "difficulty": payload.difficulty,
            "vuln_type": payload.vuln_type,
            "user_id": user["id"],
        },
    )

    # Dispatch Celery task
    run_ctf_job.delay(job_id, {"prompt": payload.prompt, "difficulty": payload.difficulty, "vuln_type": payload.vuln_type, "user_id": user["id"]})

    return {"job_id": job_id, "status": "queued"}


@router.get("/{job_id}/status")
async def job_status(job_id: int, user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    job = get_job(job_id)
    if not job or job["user_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Job not found")

    return {
        "id": job["id"],
        "status": job["status"],
        "progress": job["progress"],
        "message": job["message"],
        "logs": job["logs"],
        "result": job["result"],
    }
