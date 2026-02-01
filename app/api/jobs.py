from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from pathlib import Path
import json
import time
import zipfile
import io

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

    download_url = None
    expires_at = job.get("result", {}).get("expires_at")
    download_path = job.get("result", {}).get("download_path")
    now = int(time.time())
    if download_path and expires_at and now < expires_at:
        download_url = f"/api/jobs/{job_id}/download"

    return {
        "id": job["id"],
        "status": job["status"],
        "progress": job["progress"],
        "message": job["message"],
        "logs": job["logs"],
        "result": job["result"],
        "download_url": download_url,
        "expires_at": expires_at,
    }


@router.get("/{job_id}/download")
async def job_download(job_id: int, user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    job = get_job(job_id)
    if not job or job["user_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="Job not found")

    result = job.get("result") or {}
    download_path = result.get("download_path")
    expires_at = result.get("expires_at")
    now = int(time.time())
    if not download_path or not expires_at or now >= expires_at:
        raise HTTPException(status_code=410, detail="Download expired")

    job_dir = Path(download_path)
    if not job_dir.exists():
        raise HTTPException(status_code=404, detail="Artifacts not found")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in ["app.py", "requirements.txt", "solution.txt", "metadata.json", "verify_challenge.py", "spec.json"]:
            p = job_dir / name
            if p.exists():
                zf.writestr(name, p.read_text())
    buf.seek(0)

    headers = {"Content-Disposition": f'attachment; filename="ctf_job_{job_id}.zip"'}
    return Response(content=buf.read(), media_type="application/zip", headers=headers)
