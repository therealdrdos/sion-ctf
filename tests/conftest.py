import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Set test database before importing app
os.environ["DATABASE_URL"] = "sqlite:///./test_data/test.db"


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    test_dir = Path("test_data")
    test_dir.mkdir(exist_ok=True)
    yield
    # Cleanup
    import shutil
    if test_dir.exists():
        shutil.rmtree(test_dir)


@pytest.fixture
def client():
    from app.main import app
    from app.db import init_db, get_db_path
    
    # Use test database
    import app.db as db_module
    db_module.DB_PATH = Path("test_data/test.db")
    
    init_db()
    
    with TestClient(app) as c:
        yield c
