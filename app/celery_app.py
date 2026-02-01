"""Celery application setup."""

from __future__ import annotations

import os

from celery import Celery

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "sion_ctf",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["app.tasks.ctf_tasks"],
)

# Auto-discover tasks under app.tasks
celery_app.autodiscover_tasks(["app.tasks"])

