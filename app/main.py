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

app.include_router(auth_router)


@app.get("/")
async def index(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/auth/login")
    return templates.TemplateResponse(request, "index.html", {"user": user})
