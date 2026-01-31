from pathlib import Path

from fastapi import APIRouter, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.auth.utils import create_token, decode_token, hash_password, verify_password
from app.db import get_connection

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html")


@router.post("/register")
async def register(
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
):
    if password != password_confirm:
        raise HTTPException(400, "Passwords do not match")

    if len(password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    with get_connection() as conn:
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            raise HTTPException(400, "Username already taken")

        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password)),
        )

    return RedirectResponse("/auth/login", status_code=303)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html")


@router.post("/login")
async def login(
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
):
    with get_connection() as conn:
        user = conn.execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(401, "Invalid credentials")

    token = create_token(user["id"])
    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie("token", token, httponly=True, samesite="lax", max_age=86400)
    return resp


@router.post("/logout")
async def logout():
    resp = RedirectResponse("/auth/login", status_code=303)
    resp.delete_cookie("token")
    return resp


def get_current_user(request: Request) -> dict | None:
    token = request.cookies.get("token")
    if not token:
        return None

    user_id = decode_token(token)
    if not user_id:
        return None

    with get_connection() as conn:
        user = conn.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()

    return dict(user) if user else None
