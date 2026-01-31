import secrets
import sqlite3
import string
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path("data/sion.db")

# Characters for public_path (URL-safe, easy to read/type)
PUBLIC_PATH_CHARS = string.ascii_lowercase + string.digits
PUBLIC_PATH_LENGTH = 8


def generate_public_path() -> str:
    """Generate a unique short ID for challenge public URLs."""
    return "".join(secrets.choice(PUBLIC_PATH_CHARS) for _ in range(PUBLIC_PATH_LENGTH))


def get_db_path() -> Path:
    DB_PATH.parent.mkdir(exist_ok=True)
    return DB_PATH


def _run_migrations(conn):
    """Run schema migrations."""
    cols = [row[1] for row in conn.execute("PRAGMA table_info(challenges)").fetchall()]
    if "name" not in cols:
        conn.execute("ALTER TABLE challenges ADD COLUMN name TEXT")
    if "exploit_spec" not in cols:
        conn.execute("ALTER TABLE challenges ADD COLUMN exploit_spec TEXT")
    if "public_path" not in cols:
        conn.execute("ALTER TABLE challenges ADD COLUMN public_path TEXT UNIQUE")


def init_db():
    """Create tables if they don't exist."""
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT,
                public_path TEXT UNIQUE,
                vuln_type TEXT NOT NULL,
                difficulty TEXT NOT NULL,
                description TEXT,
                app_code TEXT,
                container_id TEXT,
                container_url TEXT,
                flag TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                openai_api_key_encrypted TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS api_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                model TEXT NOT NULL,
                prompt_tokens INTEGER NOT NULL,
                completion_tokens INTEGER NOT NULL,
                total_tokens INTEGER NOT NULL,
                operation TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        """)
        _run_migrations(conn)


@contextmanager
def get_connection():
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
