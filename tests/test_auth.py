from app.auth.utils import create_token, decode_token, hash_password, verify_password


def test_password_hash():
    password = "testpassword123"
    hashed = hash_password(password)
    assert hashed != password
    assert verify_password(password, hashed)
    assert not verify_password("wrong", hashed)


def test_jwt_token():
    user_id = 42
    token = create_token(user_id)
    assert token
    assert decode_token(token) == user_id


def test_invalid_token():
    assert decode_token("invalid") is None
    assert decode_token("") is None


def test_register(client):
    resp = client.post(
        "/auth/register",
        data={"username": "testuser", "password": "password123", "password_confirm": "password123"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/auth/login"


def test_register_password_mismatch(client):
    resp = client.post(
        "/auth/register",
        data={"username": "testuser2", "password": "password123", "password_confirm": "different"},
    )
    assert resp.status_code == 400


def test_login(client):
    # Register first
    client.post(
        "/auth/register",
        data={
            "username": "logintest",
            "password": "password123",
            "password_confirm": "password123",
        },
    )
    # Login
    resp = client.post(
        "/auth/login",
        data={"username": "logintest", "password": "password123"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "token" in resp.cookies


def test_login_invalid(client):
    resp = client.post(
        "/auth/login",
        data={"username": "noexist", "password": "wrong"},
    )
    assert resp.status_code == 401


def test_protected_route_redirect(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 307 or resp.status_code == 303
