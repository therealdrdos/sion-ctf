"""Dashboard router for user settings and API usage."""

from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.auth.router import get_current_user
from app.crypto import decrypt_api_key, encrypt_api_key, mask_api_key
from app.db import get_connection

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def get_user_api_key(user_id: int) -> str | None:
    """Get decrypted API key for a user."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT openai_api_key_encrypted FROM user_settings WHERE user_id = ?",
            (user_id,),
        ).fetchone()

    if row and row["openai_api_key_encrypted"]:
        try:
            return decrypt_api_key(row["openai_api_key_encrypted"])
        except Exception:
            return None
    return None


def get_usage_stats(user_id: int) -> dict:
    """Get API usage statistics for a user."""
    with get_connection() as conn:
        # Total usage
        total = conn.execute(
            """SELECT
                COALESCE(SUM(prompt_tokens), 0) as prompt_tokens,
                COALESCE(SUM(completion_tokens), 0) as completion_tokens,
                COALESCE(SUM(total_tokens), 0) as total_tokens,
                COUNT(*) as call_count
            FROM api_usage WHERE user_id = ?""",
            (user_id,),
        ).fetchone()

        # Usage by operation
        by_operation = conn.execute(
            """SELECT
                operation,
                SUM(total_tokens) as tokens,
                COUNT(*) as calls
            FROM api_usage WHERE user_id = ?
            GROUP BY operation""",
            (user_id,),
        ).fetchall()

        # Recent calls
        recent = conn.execute(
            """SELECT model, operation, prompt_tokens, completion_tokens,
                      total_tokens, created_at
            FROM api_usage WHERE user_id = ?
            ORDER BY created_at DESC LIMIT 10""",
            (user_id,),
        ).fetchall()

    return {
        "total": dict(total) if total else {},
        "by_operation": [dict(row) for row in by_operation],
        "recent": [dict(row) for row in recent],
    }


@router.get("", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Render the dashboard page."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/auth/login", status_code=303)

    # Check if user has an API key set
    api_key = get_user_api_key(user["id"])
    api_key_masked = mask_api_key(api_key) if api_key else None

    # Get usage statistics
    usage_stats = get_usage_stats(user["id"])

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user": user,
            "api_key_set": api_key is not None,
            "api_key_masked": api_key_masked,
            "usage": usage_stats,
        },
    )


@router.post("/api-key", response_class=HTMLResponse)
async def set_api_key(request: Request, api_key: str = Form(...)):
    """Save or update user's OpenAI API key."""
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/auth/login", status_code=303)

    # Basic validation
    api_key = api_key.strip()
    if not api_key:
        return RedirectResponse("/dashboard?error=empty_key", status_code=303)

    # Encrypt and store
    encrypted = encrypt_api_key(api_key)

    with get_connection() as conn:
        # Upsert the API key
        existing = conn.execute(
            "SELECT id FROM user_settings WHERE user_id = ?", (user["id"],)
        ).fetchone()

        if existing:
            conn.execute(
                """UPDATE user_settings
                   SET openai_api_key_encrypted = ?, updated_at = CURRENT_TIMESTAMP
                   WHERE user_id = ?""",
                (encrypted, user["id"]),
            )
        else:
            conn.execute(
                "INSERT INTO user_settings (user_id, openai_api_key_encrypted) VALUES (?, ?)",
                (user["id"], encrypted),
            )

    return RedirectResponse("/dashboard?success=key_saved", status_code=303)


@router.delete("/api-key", response_class=HTMLResponse)
async def delete_api_key(request: Request):
    """Remove user's OpenAI API key."""
    user = get_current_user(request)
    if not user:
        return '<div class="text-red-400">Not authenticated</div>'

    with get_connection() as conn:
        conn.execute(
            "UPDATE user_settings SET openai_api_key_encrypted = NULL WHERE user_id = ?",
            (user["id"],),
        )

    return RedirectResponse("/dashboard?success=key_deleted", status_code=303)


def save_api_usage(
    user_id: int,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
    operation: str,
) -> None:
    """Save API usage record to database."""
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO api_usage
               (user_id, model, prompt_tokens, completion_tokens, total_tokens, operation)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, model, prompt_tokens, completion_tokens, total_tokens, operation),
        )
