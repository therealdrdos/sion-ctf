"""Auth Flask template - for authentication bypass and IDOR vulnerabilities."""

from flask import Flask, request, render_template_string, session, redirect, url_for
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ============================================================================
# CONFIGURATION
# ============================================================================
# FLAG will be injected here
FLAG = "FLAG{placeholder}"

# Simple in-memory user database
USERS = {
    "admin": {"password": "supersecretadmin", "role": "admin", "secret": FLAG},
    "user": {"password": "userpass", "role": "user", "secret": "Nothing special here"},
    "guest": {"password": "guest", "role": "guest", "secret": "Guest data"},
}


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
    {% if session.get('username') %}
        <p>Logged in as: {{ session.username }}</p>
        <a href="/logout">Logout</a> | <a href="/profile">Profile</a>
    {% else %}
        <p><a href="/login">Login</a></p>
    {% endif %}
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HOME_TEMPLATE)


# ============================================================================
# BASIC AUTH ROUTES
# ============================================================================
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <h1>Login</h1>
    <form method="POST">
        <input type="text" name="username" placeholder="Username"><br>
        <input type="password" name="password" placeholder="Password"><br>
        <button type="submit">Login</button>
    </form>
    {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
</body>
</html>
'''

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        user = USERS.get(username)
        if user and user['password'] == password:
            session['username'] = username
            session['role'] = user['role']
            return redirect(url_for('index'))
        error = "Invalid credentials"
    
    return render_template_string(LOGIN_TEMPLATE, error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


PROFILE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head><title>Profile</title></head>
<body>
    <h1>Profile: {{ username }}</h1>
    <p>Role: {{ role }}</p>
    <p>Secret: {{ secret }}</p>
</body>
</html>
'''

@app.route('/profile')
def profile():
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))
    
    user = USERS.get(username, {})
    return render_template_string(
        PROFILE_TEMPLATE,
        username=username,
        role=user.get('role', 'unknown'),
        secret=user.get('secret', '')
    )


# ============================================================================
# ADD VULNERABLE ENDPOINTS BELOW
# ============================================================================



# ============================================================================
# RUN APP
# ============================================================================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
