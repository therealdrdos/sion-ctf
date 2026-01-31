from dataclasses import dataclass

from openai import OpenAI

from app.config import settings

VULN_INFO = {
    "sqli": {
        "name": "SQL Injection",
        "description": "SQL injection allows attackers to interfere with database queries.",
        "resources": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://portswigger.net/web-security/sql-injection",
        ],
    },
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "description": "XSS enables attackers to inject malicious scripts into web pages.",
        "resources": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://portswigger.net/web-security/cross-site-scripting",
        ],
    },
    "cmdi": {
        "name": "Command Injection",
        "description": "Command injection allows execution of arbitrary OS commands.",
        "resources": [
            "https://owasp.org/www-community/attacks/Command_Injection",
            "https://portswigger.net/web-security/os-command-injection",
        ],
    },
    "path": {
        "name": "Path Traversal",
        "description": "Path traversal allows reading files outside the intended directory.",
        "resources": [
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://portswigger.net/web-security/file-path-traversal",
        ],
    },
    "idor": {
        "name": "Insecure Direct Object Reference",
        "description": "IDOR allows access to objects by manipulating references.",
        "resources": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
        ],
    },
    "auth": {
        "name": "Broken Authentication",
        "description": "Authentication flaws allow attackers to compromise user accounts.",
        "resources": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/",
        ],
    },
}

TUTORIAL_PROMPT = """You are a cybersecurity educator creating a tutorial for a CTF challenge.

Generate educational content for the following challenge:

Vulnerability type: {vuln_type}
Difficulty: {difficulty}
Challenge description: {description}

Create a tutorial with:
1. Three progressive hints (easy to more specific)
2. A complete step-by-step walkthrough
3. The exact solution with explanation

Format your response as JSON:
{{
    "hints": [
        "First gentle hint...",
        "More specific hint...",
        "Very specific hint pointing to the solution..."
    ],
    "walkthrough": "Step-by-step guide to solving the challenge...",
    "solution": "Complete solution with commands/payloads..."
}}

Make it educational - explain WHY the vulnerability works, not just HOW to exploit it.
"""


@dataclass
class Tutorial:
    hints: list[str]
    walkthrough: str
    solution: str
    vuln_name: str
    vuln_description: str
    resources: list[str]


def generate_tutorial(
    vuln_type: str,
    difficulty: str,
    description: str,
    exploit_hint: str = "",
) -> Tutorial | None:
    vuln_info = VULN_INFO.get(vuln_type, VULN_INFO.get("sqli"))

    if not settings.openai_api_key:
        return Tutorial(
            hints=[
                "Look at user inputs in the application.",
                f"This challenge involves {vuln_info['name']}.",
                exploit_hint or "Try manipulating the input parameters.",
            ],
            walkthrough="Tutorial generation requires API key.",
            solution="Solution generation requires API key.",
            vuln_name=vuln_info["name"],
            vuln_description=vuln_info["description"],
            resources=vuln_info["resources"],
        )

    client = OpenAI(api_key=settings.openai_api_key)

    prompt = TUTORIAL_PROMPT.format(
        vuln_type=vuln_info["name"],
        difficulty=difficulty,
        description=description,
    )

    try:
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.7,
            max_tokens=2000,
        )

        content = response.choices[0].message.content
        if not content:
            return None

        # Parse JSON response
        import json

        if "```json" in content:
            content = content.split("```json")[1].split("```")[0]
        elif "```" in content:
            content = content.split("```")[1].split("```")[0]

        data = json.loads(content.strip())

        return Tutorial(
            hints=data.get("hints", []),
            walkthrough=data.get("walkthrough", ""),
            solution=data.get("solution", ""),
            vuln_name=vuln_info["name"],
            vuln_description=vuln_info["description"],
            resources=vuln_info["resources"],
        )

    except Exception:
        return Tutorial(
            hints=[
                "Examine user inputs carefully.",
                exploit_hint or "Look for common vulnerabilities.",
            ],
            walkthrough="Error generating tutorial.",
            solution="Error generating solution.",
            vuln_name=vuln_info["name"],
            vuln_description=vuln_info["description"],
            resources=vuln_info["resources"],
        )
