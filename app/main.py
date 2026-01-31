from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.db import init_db

BASE_DIR = Path(__file__).parent
templates_dir = BASE_DIR / "templates"
static_dir = BASE_DIR / "static"
templates_dir.mkdir(exist_ok=True)
static_dir.mkdir(exist_ok=True)

templates = Jinja2Templates(directory=str(templates_dir))


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="SION-CTF", version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/health")
async def health():
    return {"status": "ok"}


# Import routers after app is created to avoid circular imports
from app.auth.router import get_current_user  # noqa: E402
from app.auth.router import router as auth_router  # noqa: E402
from app.ctf.router import router as ctf_router  # noqa: E402
from app.tutorial.router import router as tutorial_router  # noqa: E402

app.include_router(auth_router)
app.include_router(ctf_router)
app.include_router(tutorial_router)


@app.get("/")
async def index(request: Request):
    from app.db import get_connection

    user = get_current_user(request)
    if not user:
        return RedirectResponse("/auth/login")

    with get_connection() as conn:
        challenges = conn.execute(
            "SELECT * FROM challenges WHERE user_id = ? ORDER BY created_at DESC LIMIT 5",
            (user["id"],),
        ).fetchall()

    return templates.TemplateResponse(
        request,
        "index.html",
        {"user": user, "challenges": [dict(c) for c in challenges]},
    )
