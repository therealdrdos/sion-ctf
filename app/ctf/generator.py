import ast
import json
import secrets
from dataclasses import dataclass

from openai import OpenAI

from app.dashboard.router import get_user_api_key, save_api_usage

VULN_DESCRIPTIONS = {
    "sqli": "SQL Injection - User input is concatenated into SQL queries without sanitization",
    "xss": "Cross-Site Scripting - User input is reflected in HTML without escaping",
    "cmdi": "Command Injection - User input is passed to shell commands without sanitization",
    "path": "Path Traversal - User can access files outside intended directory using ../ sequences",
    "idor": "Insecure Direct Object Reference - User can access other users' data by changing IDs",
    "auth": "Broken Authentication - Weak password checks, session issues, or auth bypass",
}

SYSTEM_PROMPT = """You are a CTF challenge generator. Generate a vulnerable Flask web application.

CRITICAL RULES:
1. Generate a SINGLE Python file with Flask app containing the vulnerability
2. The flag MUST be stored as a variable or in a file/database that is returned when the exploit succeeds
3. The exploit must OUTPUT the flag - e.g. SQL injection returns the flag from a table, command injection cats a flag file, path traversal reads flag.txt, etc.
4. The flag format is FLAG{...} - use EXACTLY the flag provided in the prompt
5. Keep code minimal, use render_template_string for HTML
6. App MUST run with: app.run(host='0.0.0.0', port=5000)

EXAMPLES of proper flag placement:
- SQL Injection: Store flag in a database table, vulnerable query can extract it
- Command Injection: Write flag to /tmp/flag.txt, vulnerable endpoint can cat it
- Path Traversal: Put flag in a file outside webroot that can be accessed via ../
- XSS: Store flag in a cookie or hidden admin page

OUTPUT FORMAT - Return valid JSON:
{
    "name": "Short creative challenge name (2-4 words)",
    "app_code": "# Python Flask code - MUST contain the exact flag provided",
    "requirements": "flask",
    "flag": "FLAG{exact_flag_from_prompt}",
    "vuln_description": "Where the vulnerability is and how to trigger it",
    "exploit_hint": "What technique to use"
}"""


@dataclass
class CTFChallenge:
    name: str
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


def generate_ctf(
    prompt: str, difficulty: str, vuln_types: list[str], user_id: int, max_attempts: int = 3
) -> CTFChallenge | None:
    api_key = get_user_api_key(user_id)
    if not api_key:
        return None

    client = OpenAI(api_key=api_key)

    for _ in range(max_attempts):
        try:
            user_prompt = build_prompt(prompt, difficulty, vuln_types)
            # Extract the flag we asked for from the prompt
            expected_flag = user_prompt.split("The flag to hide in the application: ")[1].split("\n")[0]

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

            # Track API usage
            if response.usage:
                save_api_usage(
                    user_id=user_id,
                    model=response.model,
                    prompt_tokens=response.usage.prompt_tokens,
                    completion_tokens=response.usage.completion_tokens,
                    total_tokens=response.usage.total_tokens,
                    operation="ctf_generate",
                )

            content = response.choices[0].message.content
            if not content:
                continue

            content = response.choices[0].message.content
            if not content:
                continue

            data = parse_response(content)
            if not data:
                continue

            app_code = data.get("app_code", "")
            app_code = app_code.replace("\\n", "\n").replace("\\t", "\t")

            if not validate_code(app_code):
                continue

            # Verify the flag is actually in the code
            if expected_flag not in app_code:
                continue

            return CTFChallenge(
                name=data.get("name", "Unnamed Challenge"),
                app_code=app_code,
                requirements=data.get("requirements", "flask"),
                flag=expected_flag,
                vuln_description=data.get("vuln_description", ""),
                exploit_hint=data.get("exploit_hint", ""),
                difficulty=difficulty,
                vuln_types=vuln_types,
            )
        except Exception:
            continue

    return None
