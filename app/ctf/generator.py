import ast
import json
import secrets
from dataclasses import dataclass

from openai import OpenAI

from app.config import settings

VULN_DESCRIPTIONS = {
    "sqli": "SQL Injection - User input is concatenated into SQL queries without sanitization",
    "xss": "Cross-Site Scripting - User input is reflected in HTML without escaping",
    "cmdi": "Command Injection - User input is passed to shell commands without sanitization",
    "path": "Path Traversal - User can access files outside intended directory using ../ sequences",
    "idor": "Insecure Direct Object Reference - User can access other users' data by changing IDs",
    "auth": "Broken Authentication - Weak password checks, session issues, or auth bypass",
}

SYSTEM_PROMPT = """You are a CTF challenge generator. Generate a vulnerable Flask web application.

IMPORTANT RULES:
1. Generate a SINGLE Python file with Flask app containing the vulnerability
2. The app must have a clear attack vector that can be exploited
3. Include a flag in format FLAG{...} that can only be retrieved by exploiting the vulnerability
4. The flag must be hidden and only accessible through successful exploitation
5. Keep the code minimal and focused on the vulnerability
6. Include basic HTML templates inline using render_template_string
7. The app MUST run with: app.run(host='0.0.0.0', port=5000)

OUTPUT FORMAT - Return valid JSON with these exact keys:
{
    "app_code": "# Full Python Flask application code here",
    "requirements": "flask\\nwerkzeug",
    "flag": "FLAG{the_actual_flag}",
    "vuln_description": "Brief description of where the vulnerability is",
    "exploit_hint": "Hint about how to exploit it"
}"""


@dataclass
class CTFChallenge:
    app_code: str
    requirements: str
    flag: str
    vuln_description: str
    exploit_hint: str
    difficulty: str
    vuln_types: list[str]


def generate_flag() -> str:
    return f"FLAG{{{secrets.token_hex(16)}}}"


def build_prompt(prompt: str, difficulty: str, vuln_types: list[str]) -> str:
    vuln_desc = "\n".join(f"- {VULN_DESCRIPTIONS.get(v, v)}" for v in vuln_types)
    difficulty_hints = {
        "easy": "Make the vulnerability obvious and easy to spot. Minimal obfuscation.",
        "medium": "Add some misdirection but keep the core vulnerability accessible.",
        "hard": "Make it challenging to find. Add decoys and require multiple steps.",
    }

    flag = generate_flag()

    return f"""Create a vulnerable Flask web application with:

User's request: {prompt}

Difficulty: {difficulty}
{difficulty_hints.get(difficulty, "")}

Required vulnerabilities (include at least one):
{vuln_desc}

The flag to hide in the application: {flag}

Remember: The flag should only be retrievable by successfully exploiting the vulnerability."""


def parse_response(content: str) -> dict | None:
    try:
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0]
        elif "```" in content:
            content = content.split("```")[1].split("```")[0]

        return json.loads(content.strip())
    except (json.JSONDecodeError, IndexError):
        return None


def validate_code(code: str) -> bool:
    """Check if the generated Python code is syntactically valid."""
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False


def generate_ctf(prompt: str, difficulty: str, vuln_types: list[str]) -> CTFChallenge | None:
    if not settings.openai_api_key:
        return None

    try:
        client = OpenAI(api_key=settings.openai_api_key)
        user_prompt = build_prompt(prompt, difficulty, vuln_types)

        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
            temperature=0.7,
            max_tokens=4000,
        )
    except Exception:
        return None

    content = response.choices[0].message.content
    if not content:
        return None

    data = parse_response(content)
    if not data:
        return None

    app_code = data.get("app_code", "")
    # Fix escaped newlines - model sometimes outputs \\n instead of \n
    app_code = app_code.replace("\\n", "\n").replace("\\t", "\t")

    if not validate_code(app_code):
        return None

    return CTFChallenge(
        app_code=app_code,
        requirements=data.get("requirements", "flask"),
        flag=data.get("flag", ""),
        vuln_description=data.get("vuln_description", ""),
        exploit_hint=data.get("exploit_hint", ""),
        difficulty=difficulty,
        vuln_types=vuln_types,
    )
