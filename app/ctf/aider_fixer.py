"""Aider integration for fixing CTF code.

Uses Aider's Python API to fix Flask apps that crash or fail validation.
This is more robust than custom agent implementations because Aider:
- Has mature diff/edit capabilities
- Handles context intelligently
- Has years of prompt engineering refinement
"""

import json
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.ctf.generator import ExploitSpec

logger = logging.getLogger(__name__)


@dataclass
class AiderResult:
    """Result of an Aider fix attempt."""

    success: bool
    code: str | None
    message: str
    tokens_used: int = 0


def fix_with_aider(
    app_code: str,
    error: str,
    spec: "ExploitSpec",
    flag: str,
    api_key: str,
    model: str = "gpt-4.1-mini",
) -> AiderResult:
    """
    Use Aider to fix a Flask app.

    Args:
        app_code: The current (broken) Flask app code
        error: Error message (crash logs or validation failure)
        spec: The exploit specification the app must satisfy
        flag: The flag that must be returned by the exploit
        api_key: OpenAI API key
        model: Model to use (default: gpt-4.1-mini)

    Returns:
        AiderResult with fixed code or error message
    """
    # Build the fix instruction
    instruction = _build_fix_instruction(error, spec, flag)

    logger.info("=" * 60)
    logger.info("[AIDER] Starting fix")
    logger.info("=" * 60)
    logger.info(f"[AIDER] Error: {error[:200]}...")
    logger.info(f"[AIDER] Model: {model}")

    # Create a temporary directory for Aider to work in
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        app_file = tmppath / "app.py"

        # Write the app code
        app_file.write_text(app_code)

        # Initialize git repo (Aider needs this)
        subprocess.run(
            ["git", "init"],
            cwd=tmpdir,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "aider@ctf.local"],
            cwd=tmpdir,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Aider"],
            cwd=tmpdir,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "add", "app.py"],
            cwd=tmpdir,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "initial"],
            cwd=tmpdir,
            capture_output=True,
            check=True,
        )

        logger.info(f"[AIDER] Created temp repo at {tmpdir}")
        logger.info(f"[AIDER] Instruction: {instruction[:300]}...")

        try:
            # Use Aider's Python API
            result = _run_aider(
                app_file=app_file,
                instruction=instruction,
                api_key=api_key,
                model=model,
            )

            if result.success and result.code:
                # Verify flag is still in the code
                if flag not in result.code:
                    logger.warning("[AIDER] Fixed code missing flag!")
                    return AiderResult(
                        success=False,
                        code=None,
                        message="Aider removed the flag from the code",
                    )

                logger.info("[AIDER] Fix successful")
                return result

            return result

        except Exception as e:
            logger.error(f"[AIDER] Exception: {e}")
            return AiderResult(
                success=False,
                code=None,
                message=f"Aider error: {str(e)}",
            )


def _build_fix_instruction(error: str, spec: "ExploitSpec", flag: str) -> str:
    """Build the instruction for Aider to fix the code."""
    return f"""Fix this Flask app. 

ERROR:
{error}

REQUIREMENTS - The app MUST satisfy these tests:

1. EXPLOIT TEST (must return the flag):
   - Method: {spec.exploit_method}
   - Path: {spec.exploit_path}
   - Parameters: {json.dumps(spec.exploit_params)}
   - Expected: Response must contain "{flag}"

2. SAFE TEST (must NOT return the flag):
   - Method: {spec.safe_method}
   - Path: {spec.safe_path}
   - Parameters: {json.dumps(spec.safe_params)}
   - Expected: Response must NOT contain the flag

3. HEALTH CHECK:
   - GET /health must return "OK"

RULES:
- Do NOT remove or change the FLAG variable
- Use Flask 3.x patterns (no @app.before_first_request)
- Keep the app.run(host='0.0.0.0', port=5000) at the end
- Fix the specific error while maintaining the vulnerability"""


def _run_aider(
    app_file: Path,
    instruction: str,
    api_key: str,
    model: str,
) -> AiderResult:
    """Run Aider using its Python API."""
    # Import here to avoid loading aider at module level
    from aider.coders import Coder
    from aider.io import InputOutput
    from aider.models import Model

    # Set up environment with API key
    old_key = os.environ.get("OPENAI_API_KEY")
    os.environ["OPENAI_API_KEY"] = api_key

    try:
        # Create non-interactive IO
        io = InputOutput(
            yes=True,  # Auto-confirm all prompts
            chat_history_file=None,
            input_history_file=None,
        )

        # Create the model
        aider_model = Model(model)

        # Create the coder
        coder = Coder.create(
            main_model=aider_model,
            fnames=[str(app_file)],
            io=io,
            auto_commits=False,  # We don't need git commits
            stream=False,  # Don't stream output
        )

        logger.info("[AIDER] Running coder...")

        # Run the fix instruction
        coder.run(instruction)

        # Read the (hopefully) fixed code
        fixed_code = app_file.read_text()

        # Check if code was actually modified
        logger.info(f"[AIDER] Code length: {len(fixed_code)} chars")

        return AiderResult(
            success=True,
            code=fixed_code,
            message="Aider fix completed",
        )

    except Exception as e:
        logger.error(f"[AIDER] Coder error: {e}")
        return AiderResult(
            success=False,
            code=None,
            message=f"Aider coder error: {str(e)}",
        )

    finally:
        # Restore original API key
        if old_key is not None:
            os.environ["OPENAI_API_KEY"] = old_key
        elif "OPENAI_API_KEY" in os.environ:
            del os.environ["OPENAI_API_KEY"]


def fix_crash_with_aider(
    app_code: str,
    crash_logs: str,
    spec: "ExploitSpec",
    flag: str,
    api_key: str,
) -> AiderResult:
    """Convenience function to fix a container crash."""
    error = f"Container crashed with the following logs:\n\n{crash_logs}"
    return fix_with_aider(app_code, error, spec, flag, api_key)


def fix_validation_with_aider(
    app_code: str,
    validation_error: str,
    spec: "ExploitSpec",
    flag: str,
    api_key: str,
) -> AiderResult:
    """Convenience function to fix a validation failure."""
    error = f"Validation failed:\n\n{validation_error}"
    return fix_with_aider(app_code, error, spec, flag, api_key)
