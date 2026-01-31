"""Flask app templates for CTF generation."""

from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent


def get_template(name: str) -> str:
    """Load a template by name."""
    template_path = TEMPLATES_DIR / f"{name}.py"
    if not template_path.exists():
        raise ValueError(f"Template '{name}' not found")
    return template_path.read_text()


def get_template_for_vuln(vuln_type: str) -> tuple[str, str]:
    """Get the appropriate template for a vulnerability type.
    
    Returns (template_name, template_code).
    """
    mapping = {
        "sqli": "sqlite",
        "cmdi": "shell",
        "path": "files",
        "auth": "auth",
        "idor": "auth",
        "xss": "base",
    }
    template_name = mapping.get(vuln_type, "base")
    return template_name, get_template(template_name)


def list_templates() -> list[str]:
    """List all available templates."""
    return [p.stem for p in TEMPLATES_DIR.glob("*.py") if p.stem != "__init__"]
