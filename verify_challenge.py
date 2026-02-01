"""
Verify a deployed CTF app using an exploit specification.

Usage:
    python verify_challenge.py spec.json

Environment:
    TARGET_URL (optional) - base URL of the running app (default: http://127.0.0.1:5000)
    FLAG (optional) - expected flag; if absent, the spec must include "flag"
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict

import httpx


def load_spec(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def send_request(method: str, url: str, params: dict[str, Any]) -> str:
    method = method.upper()
    if method == "POST":
        resp = httpx.post(url, data=params, timeout=10, follow_redirects=True)
    else:
        resp = httpx.get(url, params=params, timeout=10, follow_redirects=True)
    resp.raise_for_status()
    return resp.text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("spec_path", help="Path to spec JSON containing exploit/safe requests")
    args = parser.parse_args()

    spec = load_spec(args.spec_path)

    base_url = os.environ.get("TARGET_URL", "http://127.0.0.1:5000").rstrip("/")
    expected_flag = os.environ.get("FLAG") or spec.get("flag")
    if not expected_flag:
        print("WARNING: expected flag not provided (env FLAG or spec.flag)", file=sys.stderr)
        expected_flag = "FLAG"
    exploit_url = f"{base_url}{spec['exploit_path']}"
    safe_url = f"{base_url}{spec['safe_path']}"

    try:
        exploit_text = send_request(spec["exploit_method"], exploit_url, spec.get("exploit_params", {}))
    except Exception as e:
        print(f"ERROR: exploit request failed: {e}", file=sys.stderr)
        return 1

    if expected_flag not in exploit_text:
        preview = exploit_text[:300].replace("\n", "\\n")
        print(f"ERROR: exploit did not return flag. Response preview: {preview}", file=sys.stderr)
        return 1

    try:
        safe_text = send_request(spec["safe_method"], safe_url, spec.get("safe_params", {}))
    except Exception as e:
        # If safe request fails entirely, treat as blocked (success)
        print(f"INFO: safe request failed, treating as blocked: {e}", file=sys.stderr)
        return 0

    if expected_flag in safe_text:
        preview = safe_text[:300].replace("\n", "\\n")
        print(f"ERROR: safe request returned flag. Response preview: {preview}", file=sys.stderr)
        return 1

    print("OK: exploit returns flag, safe request blocked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
