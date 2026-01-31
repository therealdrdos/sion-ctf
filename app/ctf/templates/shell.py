"""Shell Flask template - for command injection vulnerabilities."""

from flask import Flask, request, render_template_string
import subprocess
import os

app = Flask(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================
# FLAG will be injected here
FLAG = "FLAG{placeholder}"
FLAG_FILE = '/tmp/flag.txt'


# ============================================================================
# SETUP
# ============================================================================
def setup():
    """Create the flag file."""
    with open(FLAG_FILE, 'w') as f:
        f.write(FLAG)


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
<head><title>Network Tools</title></head>
<body>
    <h1>Network Tools</h1>
    <p>Enter a host to ping or lookup.</p>
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
setup()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
