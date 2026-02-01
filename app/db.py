import secrets
import sqlite3
import string
from contextlib import contextmanager
from pathlib import Path
import json

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
        # SQLite doesn't support ADD COLUMN with UNIQUE, so add column first then create index
        conn.execute("ALTER TABLE challenges ADD COLUMN public_path TEXT")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_challenges_public_path ON challenges(public_path)")

    # Jobs table migrations
    job_cols = [row[1] for row in conn.execute("PRAGMA table_info(jobs)").fetchall()]
    if job_cols:
        # Table exists; ensure new columns if added later (none for now)
        pass
    else:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                progress REAL DEFAULT 0,
                message TEXT,
                logs TEXT,
                result TEXT,
                payload TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )


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

            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                progress REAL DEFAULT 0,
                message TEXT,
                logs TEXT,
                result TEXT,
                payload TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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


# Job helpers
def create_job(user_id: int, payload: dict) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO jobs (user_id, status, progress, message, logs, payload)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, "queued", 0.0, "Queued", "[]", json.dumps(payload)),
        )
        return cursor.lastrowid


def update_job_status(job_id: int, status: str, message: str | None = None, progress: float | None = None):
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE jobs
            SET status = ?, message = COALESCE(?, message), progress = COALESCE(?, progress), updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (status, message, progress, job_id),
        )


def append_job_log(job_id: int, line: str):
    with get_connection() as conn:
        row = conn.execute("SELECT logs FROM jobs WHERE id = ?", (job_id,)).fetchone()
        logs = []
        if row and row["logs"]:
            try:
                logs = json.loads(row["logs"])
            except Exception:
                logs = []
        logs.append(line)
        # Cap logs to last 200 lines to avoid bloat
        if len(logs) > 200:
            logs = logs[-200:]
        conn.execute(
            """
            UPDATE jobs
            SET logs = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (json.dumps(logs), job_id),
        )


def set_job_result(job_id: int, status: str, message: str, result: dict | None = None):
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE jobs
            SET status = ?, message = ?, result = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (status, message, json.dumps(result or {}), job_id),
        )


def get_job(job_id: int) -> dict | None:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if not row:
            return None
        data = dict(row)
        try:
            data["logs"] = json.loads(data.get("logs") or "[]")
        except Exception:
            data["logs"] = []
        try:
            data["payload"] = json.loads(data.get("payload") or "{}")
        except Exception:
            data["payload"] = {}
        try:
            data["result"] = json.loads(data.get("result") or "{}")
        except Exception:
            data["result"] = {}
        return data
