from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse

from app.auth.router import get_current_user
from app.ctf.generator import generate_ctf as gen_ctf
from app.db import get_connection

router = APIRouter(prefix="/ctf", tags=["ctf"])


@router.post("/generate", response_class=HTMLResponse)
async def generate_ctf(
    request: Request,
    prompt: str = Form(...),
    difficulty: str = Form("easy"),
    vuln_types: str = Form("sqli"),
):
    """Generate a CTF challenge. Returns HTMX-compatible HTML fragment."""
    user = get_current_user(request)
    if not user:
        return '<div class="p-3 bg-red-900 rounded text-red-200">Not authenticated</div>'

    vuln_list = vuln_types.split(",") if vuln_types else ["sqli"]

    html = f"""
    <div class="p-3 bg-gray-700 rounded">
        <p class="text-sm text-green-400 font-medium">Generating CTF...</p>
        <p class="text-sm text-gray-300 mt-1">{prompt}</p>
        <p class="text-xs text-gray-500 mt-2">
            Difficulty: {difficulty} | Vulns: {", ".join(vuln_list)}
        </p>
    </div>
    """

    challenge = gen_ctf(prompt, difficulty, vuln_list)

    if not challenge:
        return (
            html
            + """
        <div class="p-3 bg-red-900 rounded text-red-200 mt-2">
            Failed to generate CTF. Check API key or try again.
        </div>
        """
        )

    with get_connection() as conn:
        cursor = conn.execute(
            """INSERT INTO challenges (user_id, vuln_type, difficulty, description, flag, status)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                user["id"],
                ",".join(challenge.vuln_types),
                challenge.difficulty,
                challenge.vuln_description,
                challenge.flag,
                "generated",
            ),
        )
        challenge_id = cursor.lastrowid

    return (
        html
        + f"""
    <div class="p-3 bg-green-900 rounded text-green-200 mt-2">
        <p class="font-medium">CTF Generated!</p>
        <p class="text-sm mt-1">{challenge.vuln_description}</p>
        <p class="text-xs text-green-400 mt-2">Challenge ID: {challenge_id}</p>
        <p class="text-xs text-gray-400 mt-1">Hint: {challenge.exploit_hint}</p>
        <div class="mt-3 flex gap-2">
            <a href="/tutorial/{challenge_id}"
               class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-sm">
                View Tutorial
            </a>
        </div>
        <p class="text-sm text-yellow-400 mt-2">Container deployment coming next...</p>
    </div>
    """
    )
