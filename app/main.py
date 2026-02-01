import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.db import init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent
templates_dir = BASE_DIR / "templates"
static_dir = BASE_DIR / "static"
templates_dir.mkdir(exist_ok=True)
static_dir.mkdir(exist_ok=True)

templates = Jinja2Templates(directory=str(templates_dir))


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("SION-CTF started")
    yield
    # Cleanup on shutdown
    try:
        from app.ctf.router import get_docker_manager

        mgr = get_docker_manager()
        if mgr:
            logger.info("Cleaning up CTF containers...")
            mgr.cleanup_all_ctf_containers()
    except Exception as e:
        logger.warning(f"Cleanup error: {e}")


app = FastAPI(title="SION-CTF", version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/health")
async def health():
    return {"status": "ok"}


# Import routers after app is created to avoid circular imports
from app.auth.router import get_current_user  # noqa: E402
from app.auth.router import router as auth_router  # noqa: E402
from app.ctf.router import router as ctf_router  # noqa: E402
from app.dashboard.router import router as dashboard_router  # noqa: E402
from app.tutorial.router import router as tutorial_router  # noqa: E402
from app.api.jobs import router as jobs_router  # noqa: E402

app.include_router(auth_router)
app.include_router(ctf_router)
app.include_router(dashboard_router)
app.include_router(tutorial_router)
app.include_router(jobs_router)


@app.get("/")
async def index(request: Request):
    from app.config import settings
    from app.db import get_connection

    user = get_current_user(request)
    if not user:
        return RedirectResponse("/auth/login")

    with get_connection() as conn:
        challenges = conn.execute(
            "SELECT * FROM challenges WHERE user_id = ? ORDER BY created_at DESC LIMIT 5",
            (user["id"],),
        ).fetchall()
        # Find active (running) challenge
        active = conn.execute(
            "SELECT * FROM challenges WHERE user_id = ? AND status = 'running' ORDER BY created_at DESC LIMIT 1",
            (user["id"],),
        ).fetchone()

    # Calculate public URL for active challenge
    active_dict = None
    if active:
        active_dict = dict(active)
        # Use public URL if proxy is configured
        if settings.challenge_proxy_url and active_dict.get("public_path"):
            active_dict["display_url"] = (
                f"{settings.challenge_proxy_url.rstrip('/')}/{active_dict['public_path']}/"
            )
        else:
            active_dict["display_url"] = active_dict.get("container_url", "")

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "user": user,
            "challenges": [dict(c) for c in challenges],
            "active": active_dict,
        },
    )
