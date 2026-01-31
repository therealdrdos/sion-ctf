"""SQLite Flask template - for SQL injection vulnerabilities."""

from flask import Flask, request, render_template_string, g
import sqlite3
import os

app = Flask(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================
DATABASE = '/tmp/ctf_app.db'
# FLAG will be injected here
FLAG = "FLAG{placeholder}"


# ============================================================================
# DATABASE SETUP
# ============================================================================
def get_db():
    """Get database connection for current request."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    """Close database connection at end of request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize database with tables and seed data."""
    # Remove old database
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
    
    db = get_db()
    
    # Create users table with flag in admin password
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # Seed with admin user (password contains flag)
    db.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        ("admin", FLAG)
    )
    db.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        ("user", "userpass123")
    )
    
    db.commit()


# ============================================================================
# HEALTH CHECK (required)
# ============================================================================
@app.route('/health')
def health():
    return 'OK'


# ============================================================================
# HOME PAGE
# ============================================================================
HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head><title>App</title></head>
<body>
    <h1>Welcome</h1>
    <p>Please login or search.</p>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HOME_TEMPLATE)


# ============================================================================
# ADD VULNERABLE ENDPOINTS BELOW
# ============================================================================



# ============================================================================
# INITIALIZE AND RUN
# ============================================================================
with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
