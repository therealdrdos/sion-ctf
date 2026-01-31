import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import httpx
from openai import OpenAI

from app.dashboard.router import get_user_api_key, save_api_usage

SOLUTION_PROMPT = """You are a CTF validator. Given a vulnerable Flask application and the \
KNOWN vulnerability details, generate a Python script that exploits it.

You are NOT trying to discover the vulnerability - it has already been identified.
Your job is to create a working exploit based on the provided vulnerability information.

The exploit script must:
1. Be a standalone Python script using only 'requests' library
2. Take the target URL as first command line argument
3. Print ONLY the flag (format: FLAG{...}) to stdout on success
4. Exit with code 0 on success, non-zero on failure

Use the provided exploit payload as a starting point - adapt it into a working Python script.

OUTPUT FORMAT - Return ONLY valid Python code, no markdown, no explanation:
"""


@dataclass
class Solution:
    exploit_code: str
    explanation: str


@dataclass
class ValidationResult:
    success: bool
    flag_found: str | None
    error: str | None


def generate_solution(
    app_code: str,
    vuln_types: list[str],
    vuln_description: str,
    exploit_hint: str,
    exploit_payload: str,
    user_id: int,
) -> Solution | None:
    api_key = get_user_api_key(user_id)
    if not api_key:
        return None

    client = OpenAI(api_key=api_key)

    prompt = f"""Vulnerable Flask application code:

```python
{app_code}
```

KNOWN VULNERABILITY DETAILS:
- Type: {", ".join(vuln_types)}
- Location/Description: {vuln_description}
- Technique: {exploit_hint}
- Example payload: {exploit_payload}

Generate a Python script that uses this known vulnerability to retrieve the flag.
The exploit payload above shows exactly how to trigger the vulnerability - adapt it into a working script."""

    response = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[
            {"role": "system", "content": SOLUTION_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,
        max_tokens=2000,
    )

    # Track API usage
    if response.usage:
        save_api_usage(
            user_id=user_id,
            model=response.model,
            prompt_tokens=response.usage.prompt_tokens,
            completion_tokens=response.usage.completion_tokens,
            total_tokens=response.usage.total_tokens,
            operation="validation",
        )

    content = response.choices[0].message.content
    if not content:
        return None

    # Clean up response
    code = content.strip()
    if code.startswith("```python"):
        code = code[9:]
    if code.startswith("```"):
        code = code[3:]
    if code.endswith("```"):
        code = code[:-3]

    return Solution(exploit_code=code.strip(), explanation="")


def run_exploit(exploit_code: str, target_url: str, timeout: int = 30) -> ValidationResult:
    """Run the exploit script against the target and capture output."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(exploit_code)
        script_path = Path(f.name)

    try:
        result = subprocess.run(
            ["python3", str(script_path), target_url],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        output = result.stdout.strip()
        flag_match = re.search(r"FLAG\{[^}]+\}", output)

        if flag_match:
            return ValidationResult(success=True, flag_found=flag_match.group(0), error=None)

        return ValidationResult(
            success=False,
            flag_found=None,
            error=result.stderr or "No flag found in output",
        )

    except subprocess.TimeoutExpired:
        return ValidationResult(success=False, flag_found=None, error="Exploit timed out")
    except Exception as e:
        return ValidationResult(success=False, flag_found=None, error=str(e))
    finally:
        script_path.unlink(missing_ok=True)


def check_container_health(url: str, timeout: int = 5) -> bool:
    """Check if the container is responding."""
    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True)
        return resp.status_code < 500
    except Exception:
        return False


def validate_challenge(
    app_code: str,
    expected_flag: str,
    target_url: str,
    vuln_types: list[str],
    vuln_description: str,
    exploit_hint: str,
    exploit_payload: str,
    user_id: int,
    max_retries: int = 3,
) -> tuple[bool, Solution | None, str]:
    """
    Validate that a CTF challenge is solvable.
    Returns (success, solution, error_message).
    """
    if not check_container_health(target_url):
        return False, None, "Container not responding"

    for attempt in range(max_retries):
        solution = generate_solution(
            app_code=app_code,
            vuln_types=vuln_types,
            vuln_description=vuln_description,
            exploit_hint=exploit_hint,
            exploit_payload=exploit_payload,
            user_id=user_id,
        )
        if not solution:
            continue

        result = run_exploit(solution.exploit_code, target_url)

        if result.success and result.flag_found == expected_flag:
            return True, solution, ""

        if result.error:
            continue

    return False, None, f"Failed to validate after {max_retries} attempts"
