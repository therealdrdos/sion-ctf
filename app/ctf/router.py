from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse

router = APIRouter(prefix="/ctf", tags=["ctf"])


@router.post("/generate", response_class=HTMLResponse)
async def generate_ctf(
    request: Request,
    prompt: str = Form(...),
    difficulty: str = Form("easy"),
    vuln_types: str = Form("sqli"),
):
    """Placeholder endpoint for CTF generation. Returns HTMX-compatible HTML fragment."""
    vuln_list = vuln_types.split(",") if vuln_types else []

    return f"""
    <div class="p-3 bg-gray-700 rounded">
        <p class="text-sm text-green-400 font-medium">Your request:</p>
        <p class="text-sm text-gray-300 mt-1">{prompt}</p>
        <p class="text-xs text-gray-500 mt-2">
            Difficulty: {difficulty} | Vulns: {", ".join(vuln_list)}
        </p>
        <p class="text-sm text-yellow-400 mt-2">CTF generation coming in next phase...</p>
    </div>
    """
