def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_db_init(client):
    from app.db import get_connection
    
    with get_connection() as conn:
        # Check tables exist
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = [t["name"] for t in tables]
        
        assert "users" in table_names
        assert "challenges" in table_names
        assert "sessions" in table_names
