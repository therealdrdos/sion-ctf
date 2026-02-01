"""Aider CLI wrapper for generating and fixing CTF apps.

Runs the aider CLI with reasoning model, architect mode, and optional auto-tests.
This wrapper prepares a temp workspace (app.py, requirements.txt, spec/tests),
invokes aider, and returns the updated code/requirements plus logs.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "o3-mini"


@dataclass
class AiderCLIResult:
    success: bool
    app_code: str | None
    requirements: str | None
    stdout: str
    stderr: str
    returncode: int


def run_aider_cli(
    *,
    app_code: str,
    requirements: str,
    instruction: str,
    api_key: str,
    model: str = DEFAULT_MODEL,
    docs_path: str | None = None,
    test_cmd: str | None = None,
    extra_files: Mapping[str, str] | None = None,
    env_vars: Mapping[str, str] | None = None,
) -> AiderCLIResult:
    """
    Run aider CLI against a temporary workspace.

    Args:
        app_code: Current app.py contents.
        requirements: Current requirements.txt contents.
        instruction: The user instruction for aider.
        api_key: OpenAI API key (passed via --api-key openai=...).
        model: Model to use (default o3-mini for reasoning).
        docs_path: Optional docs file to --read.
        test_cmd: Optional test command to run with --auto-test.
        extra_files: Optional mapping of filename -> content to include (e.g., spec.json).
        env_vars: Optional environment variables for aider process (e.g., TARGET_URL).

    Returns:
        AiderCLIResult with updated code/requirements and CLI logs.
    """
    with tempfile.TemporaryDirectory() as tmpdir_str:
        tmpdir = Path(tmpdir_str)
        app_file = tmpdir / "app.py"
        req_file = tmpdir / "requirements.txt"

        app_file.write_text(app_code)
        req_file.write_text(requirements)

        # Write any extra files (e.g., spec.json)
        extra_paths: list[Path] = []
        if extra_files:
            for name, content in extra_files.items():
                path = tmpdir / name
                path.write_text(content)
                extra_paths.append(path)

        # Initialize git repo for aider (prevents interactive prompt)
        try:
            subprocess.run(["git", "init"], cwd=tmpdir, check=True, capture_output=True)
            subprocess.run(
                ["git", "config", "user.email", "aider@ctf.local"],
                cwd=tmpdir,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Aider"],
                cwd=tmpdir,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "add", "app.py", "requirements.txt", *(p.name for p in extra_paths)],
                cwd=tmpdir,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "commit", "-m", "initial"],
                cwd=tmpdir,
                check=True,
                capture_output=True,
            )
        except Exception:
            logger.warning("Failed to init git repo for aider", exc_info=True)

        # Copy docs into temp workspace if provided
        docs_arg: Path | None = None
        if docs_path:
            src = Path(docs_path)
            if src.exists():
                docs_arg = tmpdir / src.name
                shutil.copy2(src, docs_arg)
            else:
                logger.warning("Docs file not found: %s", docs_path)

        cmd: list[str] = [
            "aider",
            "--model",
            model,
            "--architect",
            "--yes",  # non-interactive
            "--no-gitignore",  # avoid interactive prompt about .aider*
            "--api-key",
            f"openai={api_key}",
            "--message",
            instruction,
        ]

        # Attach docs for context
        if docs_arg:
            cmd.extend(["--read", docs_arg.name])

        # Auto test if provided
        if test_cmd:
            cmd.extend(["--test-cmd", test_cmd, "--auto-test"])

        # Files to edit
        edit_files: list[str] = ["app.py", "requirements.txt"]
        edit_files.extend(p.name for p in extra_paths)
        cmd.extend(edit_files)

        # Instrumentation: log environment and command (Hypothesis A: audioop missing due to Python 3.13 env)
        _debug_log(
            hypothesis_id="A",
            location="aider_cli.py:cmd",
            message="About to run aider CLI",
            data={
                "python": sys.version,
                "python_exe": sys.executable,
                "which_aider": shutil.which("aider"),
                "cmd": cmd,
                "docs_present": bool(docs_arg),
                "extra_files": list(extra_files.keys()) if extra_files else [],
                "test_cmd": test_cmd,
            },
        )

        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)

        proc = subprocess.run(
            cmd,
            cwd=tmpdir,
            capture_output=True,
            text=True,
            env=env,
        )

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        # Always attempt to read files even if aider failed
        new_app = app_file.read_text() if app_file.exists() else None
        new_req = req_file.read_text() if req_file.exists() else None

        result = AiderCLIResult(
            success=proc.returncode == 0,
            app_code=new_app,
            requirements=new_req,
            stdout=stdout,
            stderr=stderr,
            returncode=proc.returncode,
        )

        # Instrumentation: log outcome (Hypothesis B: stderr contains audioop)
        _debug_log(
            hypothesis_id="B",
            location="aider_cli.py:result",
            message="Aider CLI completed",
            data={
                "returncode": proc.returncode,
                "stderr_head": (stderr or "")[:2000],
                "stdout_head": (stdout or "")[:500],
                "has_app": new_app is not None,
                "has_req": new_req is not None,
            },
        )

        if not result.success:
            logger.warning("[AIDER CLI] failed with code %s", proc.returncode)
            logger.warning("[AIDER CLI] stderr: %s", stderr[:500])

        return result
