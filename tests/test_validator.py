import re

from app.ctf.validator import ValidationResult, run_exploit


def test_validation_result_success():
    result = ValidationResult(success=True, flag_found="FLAG{test}", error=None)
    assert result.success
    assert result.flag_found == "FLAG{test}"


def test_validation_result_failure():
    result = ValidationResult(success=False, flag_found=None, error="some error")
    assert not result.success
    assert result.error == "some error"


def test_run_exploit_simple():
    # Simple script that prints a flag
    code = """
import sys
print("FLAG{test123}")
sys.exit(0)
"""
    result = run_exploit(code, "http://localhost:9999", timeout=5)
    assert result.success
    assert result.flag_found == "FLAG{test123}"


def test_run_exploit_no_flag():
    code = """
import sys
print("no flag here")
sys.exit(0)
"""
    result = run_exploit(code, "http://localhost:9999", timeout=5)
    assert not result.success
    assert result.flag_found is None


def test_run_exploit_timeout():
    code = """
import time
time.sleep(10)
"""
    result = run_exploit(code, "http://localhost:9999", timeout=1)
    assert not result.success
    assert "timed out" in result.error.lower()


def test_flag_regex():
    pattern = r"FLAG\{[^}]+\}"
    assert re.search(pattern, "FLAG{abc123}")
    assert re.search(pattern, "prefix FLAG{test} suffix")
    assert not re.search(pattern, "FLAG{}")
    assert not re.search(pattern, "flag{test}")
