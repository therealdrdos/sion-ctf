from app.ctf.generator import (
    VULN_DESCRIPTIONS,
    build_prompt,
    parse_response,
    validate_code,
)


def test_build_prompt():
    prompt = build_prompt("A login page", "easy", ["sqli"])
    assert "login page" in prompt
    assert "easy" in prompt.lower()
    assert "SQL" in prompt


def test_build_prompt_multiple_vulns():
    prompt = build_prompt("test", "medium", ["sqli", "xss"])
    assert "SQL Injection" in prompt
    assert "Cross-Site Scripting" in prompt


def test_parse_response_json():
    response = '{"app_code": "print(1)", "flag": "FLAG{test}"}'
    result = parse_response(response)
    assert result is not None
    assert result["app_code"] == "print(1)"
    assert result["flag"] == "FLAG{test}"


def test_parse_response_with_markdown():
    response = """Here's the code:
```json
{"app_code": "x=1", "flag": "FLAG{a}"}
```
"""
    result = parse_response(response)
    assert result is not None
    assert result["app_code"] == "x=1"


def test_parse_response_invalid():
    assert parse_response("not json") is None
    assert parse_response("") is None


def test_validate_code_valid():
    assert validate_code("x = 1")
    assert validate_code("def foo(): pass")
    assert validate_code("from flask import Flask\napp = Flask(__name__)")


def test_validate_code_invalid():
    assert not validate_code("def foo(")
    assert not validate_code("x = ")


def test_vuln_descriptions_exist():
    expected = ["sqli", "xss", "cmdi", "path", "idor", "auth"]
    for vuln in expected:
        assert vuln in VULN_DESCRIPTIONS
