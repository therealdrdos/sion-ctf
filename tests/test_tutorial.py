from pathlib import Path

import pytest

from app.tutorial.generator import VULN_INFO, generate_tutorial


@pytest.fixture(autouse=True)
def init_test_db():
    """Initialize database for tutorial tests."""
    import app.db as db_module
    from app.db import init_db

    db_module.DB_PATH = Path("test_data/test.db")
    init_db()
    yield


def test_vuln_info_completeness():
    expected = ["sqli", "xss", "cmdi", "path", "idor", "auth"]
    for vuln in expected:
        assert vuln in VULN_INFO
        assert "name" in VULN_INFO[vuln]
        assert "description" in VULN_INFO[vuln]
        assert "resources" in VULN_INFO[vuln]


def test_generate_tutorial_without_api_key():
    # Without API key (user_id with no key set), should return fallback tutorial
    tutorial = generate_tutorial(
        vuln_type="sqli",
        difficulty="easy",
        description="A login form",
        user_id=99999,  # Non-existent user, no API key
    )

    assert tutorial is not None
    assert tutorial.vuln_name == "SQL Injection"
    assert len(tutorial.hints) > 0
    assert len(tutorial.resources) > 0


def test_generate_tutorial_unknown_vuln():
    tutorial = generate_tutorial(
        vuln_type="unknown_vuln",
        difficulty="medium",
        description="test",
        user_id=99999,  # Non-existent user, no API key
    )

    assert tutorial is not None
    # Falls back to sqli info
    assert tutorial.vuln_name == "SQL Injection"
