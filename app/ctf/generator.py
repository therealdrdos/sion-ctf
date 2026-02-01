import ast
import json
import logging
import secrets
from dataclasses import dataclass

from openai import OpenAI

from app.dashboard.router import get_user_api_key, save_api_usage

logger = logging.getLogger(__name__)

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
7. Use MODERN Flask (3.x) patterns only:
   - Do NOT use @app.before_first_request (removed in Flask 2.3)
   - Initialize data at module level or inside route functions
   - For database setup, create tables directly after db connection, not in decorators

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
    "exploit_hint": "What technique to use",
    "exploit_payload": "The exact HTTP request or payload to exploit the vulnerability (e.g., curl command, POST data, or URL with injection)"
}"""


@dataclass
class ExploitSpec:
    """Specification for how to exploit a vulnerability - generated BEFORE the app."""

    vuln_type: str
    difficulty: str

    # The attack that SHOULD return the flag
    exploit_method: str  # GET, POST
    exploit_path: str  # /search, /login
    exploit_params: dict  # {"username": "' OR 1=1--"}
    exploit_description: str  # "SQL injection in username field"

    # A normal request that should NOT return the flag
    safe_method: str
    safe_path: str
    safe_params: dict

    # Guidance for app generation
    app_description: str  # "Login form with SQL backend"


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
    exploit_spec: ExploitSpec | None = None  # The spec used to generate/validate


def generate_flag() -> str:
    return f"FLAG{{{secrets.token_hex(16)}}}"


EXPLOIT_SPEC_PROMPT = """You are a security expert designing CTF challenge specifications.
Given a vulnerability type and difficulty, design a SPECIFIC exploit that will be used to test a vulnerable web app.

You must provide:
1. The exact HTTP request (method, path, parameters) that exploits the vulnerability
2. A safe/normal HTTP request to the same endpoint that should NOT trigger the vulnerability
3. A description of what the vulnerable app should look like

OUTPUT FORMAT - Return valid JSON:
{
    "exploit_method": "GET or POST",
    "exploit_path": "/endpoint",
    "exploit_params": {"param": "malicious_value"},
    "exploit_description": "How this exploit works",
    "safe_method": "GET or POST",
    "safe_path": "/endpoint",
    "safe_params": {"param": "normal_value"},
    "app_description": "What the vulnerable app should do"
}

EXAMPLES by vulnerability type:

SQL Injection (easy):
- exploit: POST /login with {"username": "' OR '1'='1", "password": "x"}
- safe: POST /login with {"username": "admin", "password": "wrongpass"}

SQL Injection (hard):
- exploit: GET /search?q=1' UNION SELECT password FROM users--
- safe: GET /search?q=hello

Command Injection:
- exploit: POST /ping with {"host": "127.0.0.1; cat /tmp/flag.txt"}
- safe: POST /ping with {"host": "127.0.0.1"}

Path Traversal:
- exploit: GET /files?name=../../../tmp/flag.txt
- safe: GET /files?name=readme.txt

XSS (for flag in cookie/page):
- exploit: GET /search?q=<script>alert(1)</script> (reflected in response)
- safe: GET /search?q=hello

IDOR:
- exploit: GET /user/1 (accessing admin user data)
- safe: GET /user/999 (accessing own data)
"""


def generate_exploit_spec(
    vuln_type: str, difficulty: str, user_id: int
) -> ExploitSpec | None:
    """Generate an exploit specification BEFORE creating the vulnerable app."""
    api_key = get_user_api_key(user_id)
    if not api_key:
        logger.warning("[EXPLOIT SPEC] No API key available")
        return None

    client = OpenAI(api_key=api_key)

    vuln_desc = VULN_DESCRIPTIONS.get(vuln_type, vuln_type)
    difficulty_context = {
        "easy": "Simple, obvious vulnerability. Single step exploit.",
        "medium": "Requires some knowledge. May need parameter discovery.",
        "hard": "Complex exploit. May require chaining or multiple steps.",
    }

    prompt = f"""Design an exploit specification for:

Vulnerability Type: {vuln_type} - {vuln_desc}
Difficulty: {difficulty} - {difficulty_context.get(difficulty, "")}

Create a specific, testable exploit that can be validated with simple HTTP requests."""

    logger.info("=" * 60)
    logger.info("[EXPLOIT SPEC] GENERATING SPEC")
    logger.info("=" * 60)
    logger.info(f"[SYSTEM] {EXPLOIT_SPEC_PROMPT[:200]}...")
    logger.info(f"[USER] {prompt}")

    try:
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": EXPLOIT_SPEC_PROMPT},
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
            temperature=0.7,
            max_tokens=4000,
        )

        if response.usage:
            logger.info(
                f"[TOKENS] prompt={response.usage.prompt_tokens}, "
                f"completion={response.usage.completion_tokens}, "
                f"total={response.usage.total_tokens}"
            )
            save_api_usage(
                user_id=user_id,
                model=response.model,
                prompt_tokens=response.usage.prompt_tokens,
                completion_tokens=response.usage.completion_tokens,
                total_tokens=response.usage.total_tokens,
                operation="exploit_spec",
            )

        content = response.choices[0].message.content
        logger.info(f"[ASSISTANT] {content}")

        if not content:
            logger.warning("[EXPLOIT SPEC] Empty response")
            return None

        data = parse_response(content)
        if not data:
            logger.warning("[EXPLOIT SPEC] Failed to parse response")
            return None

        spec = ExploitSpec(
            vuln_type=vuln_type,
            difficulty=difficulty,
            exploit_method=data.get("exploit_method", "GET"),
            exploit_path=data.get("exploit_path", "/"),
            exploit_params=data.get("exploit_params", {}),
            exploit_description=data.get("exploit_description", ""),
            safe_method=data.get("safe_method", "GET"),
            safe_path=data.get("safe_path", "/"),
            safe_params=data.get("safe_params", {}),
            app_description=data.get("app_description", ""),
        )
        logger.info(f"[EXPLOIT SPEC] Created: {spec.exploit_method} {spec.exploit_path}")
        return spec

    except Exception as e:
        logger.error(f"[EXPLOIT SPEC] Error: {e}")
        return None


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


FIX_CODE_PROMPT = """You are a Python code fixer. The Flask application below crashed with an error.
Fix the code to resolve the error while keeping ALL functionality intact.

RULES:
1. Keep the SAME vulnerability and flag - do not change the security behavior
2. Only fix the specific error mentioned
3. Use modern Flask 3.x patterns (no @app.before_first_request, etc.)
4. Return ONLY the fixed Python code, no explanations or markdown"""


def fix_code(app_code: str, error_log: str, user_id: int) -> str | None:
    """Ask AI to fix code based on error logs. Returns fixed code or None."""
    api_key = get_user_api_key(user_id)
    if not api_key:
        return None

    client = OpenAI(api_key=api_key)

    prompt = f"""Original Flask application code:

```python
{app_code}
```

Error when running:
```
{error_log}
```

Fix the code to resolve this error. Return only the fixed Python code."""

    try:
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": FIX_CODE_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=4000,
        )

        if response.usage:
            save_api_usage(
                user_id=user_id,
                model=response.model,
                prompt_tokens=response.usage.prompt_tokens,
                completion_tokens=response.usage.completion_tokens,
                total_tokens=response.usage.total_tokens,
                operation="ctf_fix",
            )

        content = response.choices[0].message.content
        if not content:
            return None

        # Clean up response - remove markdown if present
        code = content.strip()
        if code.startswith("```python"):
            code = code[9:]
        if code.startswith("```"):
            code = code[3:]
        if code.endswith("```"):
            code = code[:-3]

        code = code.strip()

        # Validate the fixed code
        if not validate_code(code):
            return None

        return code

    except Exception:
        return None


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
                exploit_spec=None,
            )
        except Exception:
            continue

    return None


# =============================================================================
# Test-Driven CTF Generation (Spec-First Approach with Templates)
# =============================================================================

from app.ctf.templates import get_template_for_vuln

TEMPLATE_PROMPT = """You are a CTF challenge generator. You will ADD vulnerable code to an existing Flask app template.

The template already has the following:
- Flask app setup
- Database/file/auth setup (depending on template)
- /health endpoint
- Basic home page

Your job is to ADD the vulnerable endpoint(s) that match the exploit specification.

RULES:
1. You are supposed to leave vulnerable code on purpose, for example unsafe sql queries.
2. The exploit request MUST return the flag when exploited
3. The safe request must work but NOT return the flag
"""


def generate_ctf_from_spec(
    spec: ExploitSpec,
    flag: str,
    user_id: int,
    prompt: str = "",
) -> CTFChallenge | None:
    """Generate a CTF app using a template + AI-generated vulnerable code."""
    api_key = get_user_api_key(user_id)
    if not api_key:
        return None

    client = OpenAI(api_key=api_key)

    # Load the appropriate template
    template_name, template_code = get_template_for_vuln(spec.vuln_type)
    logger.info(f"[GENERATOR] Using template: {template_name}")

    # Inject the flag into the template
    template_code = template_code.replace('FLAG = "FLAG{placeholder}"', f'FLAG = "{flag}"')

    # Build prompt asking AI to add ONLY the vulnerable parts
    user_prompt = f"""Add vulnerable endpoint(s) to this {template_name} Flask template.

TEMPLATE FEATURES:
- Template type: {template_name}
- Has /health endpoint
- Has home page at /
{"- Has get_db() for database access" if template_name == "sqlite" else ""}
{"- Has USERS dict with admin having FLAG as secret" if template_name == "auth" else ""}
{"- Has FILES_DIR and FLAG_FILE setup" if template_name == "files" else ""}
{"- Has FLAG_FILE at /tmp/flag.txt" if template_name == "shell" else ""}

=== EXPLOIT THAT MUST WORK ===
Method: {spec.exploit_method}
Path: {spec.exploit_path}
Parameters: {json.dumps(spec.exploit_params)}
How it works: {spec.exploit_description}

When this request is made, the response MUST contain: {flag}

=== SAFE REQUEST (must NOT return flag) ===
Method: {spec.safe_method}
Path: {spec.safe_path}
Parameters: {json.dumps(spec.safe_params)}

{f"User's theme request: {prompt}" if prompt else ""}

Remember: Return ONLY the new vulnerable routes/functions to add, not the whole app."""

    logger.info("=" * 60)
    logger.info("[GENERATOR] CTF FROM TEMPLATE")
    logger.info("=" * 60)
    logger.info(f"[SYSTEM] {TEMPLATE_PROMPT[:200]}...")
    logger.info(f"[USER] {user_prompt}")

    try:
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": TEMPLATE_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
            temperature=0.7,
            max_tokens=2000,  # Reduced since we only need partial code
        )

        if response.usage:
            logger.info(
                f"[TOKENS] prompt={response.usage.prompt_tokens}, "
                f"completion={response.usage.completion_tokens}, "
                f"total={response.usage.total_tokens}"
            )
            save_api_usage(
                user_id=user_id,
                model=response.model,
                prompt_tokens=response.usage.prompt_tokens,
                completion_tokens=response.usage.completion_tokens,
                total_tokens=response.usage.total_tokens,
                operation="ctf_from_template",
            )

        content = response.choices[0].message.content
        logger.info(f"[ASSISTANT] {content}")

        if not content:
            logger.warning("[GENERATOR] Empty response from AI")
            return None

        data = parse_response(content)
        if not data:
            logger.warning("[GENERATOR] Failed to parse response")
            return None

        vulnerable_code = data.get("vulnerable_code", "")
        init_code = data.get("init_code", "")
        logger.info(f"[GENERATOR] Got vulnerable_code ({len(vulnerable_code)} chars)")

        # Clean up escaped characters
        vulnerable_code = vulnerable_code.replace("\\n", "\n").replace("\\t", "\t")
        init_code = init_code.replace("\\n", "\n").replace("\\t", "\t")

        # Insert vulnerable code into template
        app_code = _insert_code_into_template(
            template_code, vulnerable_code, init_code
        )

        if not validate_code(app_code):
            logger.warning("[GENERATOR] Generated code failed validation")
            return None

        # Verify the flag is in the code
        if flag not in app_code:
            return None

        return CTFChallenge(
            name=data.get("name", "Unnamed Challenge"),
            app_code=app_code,
            requirements="flask",
            flag=flag,
            vuln_description=spec.exploit_description,
            exploit_hint=f"{spec.exploit_method} {spec.exploit_path}",
            difficulty=spec.difficulty,
            vuln_types=[spec.vuln_type],
            exploit_spec=spec,
        )

    except Exception:
        return None


def _insert_code_into_template(template: str, vulnerable_code: str, init_code: str) -> str:
    """Insert generated code into the template at the right locations."""
    # Insert vulnerable code before the "RUN APP" section
    marker = "# ============================================================================\n# RUN APP"
    if marker in template:
        template = template.replace(
            marker,
            f"{vulnerable_code}\n\n\n{marker}"
        )
    else:
        # Fallback: insert before if __name__
        template = template.replace(
            "if __name__ == '__main__':",
            f"{vulnerable_code}\n\n\nif __name__ == '__main__':"
        )

    # Insert init code if provided
    if init_code and init_code.strip():
        # Look for init_db or setup function
        if "def init_db():" in template:
            # Insert after the init_db function definition
            template = template.replace(
                "def init_db():\n",
                f"def init_db():\n{init_code}\n"
            )
        elif "def setup():" in template:
            template = template.replace(
                "def setup():\n",
                f"def setup():\n{init_code}\n"
            )

    return template


def fix_ctf_for_spec(
    app_code: str,
    spec: ExploitSpec,
    flag: str,
    error: str,
    user_id: int,
) -> str | None:
    """Fix an app that doesn't match the exploit spec."""
    api_key = get_user_api_key(user_id)
    if not api_key:
        return None

    client = OpenAI(api_key=api_key)

    prompt = f"""The Flask app below does not pass validation. Fix it.

CURRENT CODE:
```python
{app_code}
```

VALIDATION ERROR: {error}

REQUIRED EXPLOIT (must work):
- {spec.exploit_method} {spec.exploit_path}
- Parameters: {json.dumps(spec.exploit_params)}
- Must return flag: {flag}

SAFE REQUEST (must NOT return flag):
- {spec.safe_method} {spec.safe_path}
- Parameters: {json.dumps(spec.safe_params)}

Fix the code so the exploit works and the safe request doesn't return the flag.
Return ONLY the fixed Python code, no markdown or explanations."""

    try:
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": FIX_CODE_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=4000,
        )

        if response.usage:
            save_api_usage(
                user_id=user_id,
                model=response.model,
                prompt_tokens=response.usage.prompt_tokens,
                completion_tokens=response.usage.completion_tokens,
                total_tokens=response.usage.total_tokens,
                operation="ctf_fix_spec",
            )

        content = response.choices[0].message.content
        if not content:
            return None

        code = content.strip()
        if code.startswith("```python"):
            code = code[9:]
        if code.startswith("```"):
            code = code[3:]
        if code.endswith("```"):
            code = code[:-3]

        code = code.strip()

        if not validate_code(code):
            return None

        # Verify flag still in code
        if flag not in code:
            return None

        return code

    except Exception:
        return None
