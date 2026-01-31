from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.auth.router import get_current_user
from app.db import get_connection
from app.tutorial.generator import generate_tutorial

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

router = APIRouter(prefix="/tutorial", tags=["tutorial"])


@router.get("/{challenge_id}", response_class=HTMLResponse)
async def view_tutorial(request: Request, challenge_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/auth/login")

    with get_connection() as conn:
        challenge = conn.execute(
            "SELECT * FROM challenges WHERE id = ? AND user_id = ?",
            (challenge_id, user["id"]),
        ).fetchone()

    if not challenge:
        return RedirectResponse("/")

    vuln_type = challenge["vuln_type"].split(",")[0] if challenge["vuln_type"] else "sqli"

    tutorial = generate_tutorial(
        vuln_type=vuln_type,
        difficulty=challenge["difficulty"],
        description=challenge["description"] or "",
        user_id=user["id"],
    )

    return templates.TemplateResponse(
        request,
        "tutorial.html",
        {
            "challenge": dict(challenge),
            "tutorial": tutorial,
        },
    )
