"""Files Flask template - for path traversal vulnerabilities."""

from flask import Flask, request, render_template_string, send_file, abort
import os

app = Flask(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================
# FLAG will be injected here
FLAG = "FLAG{placeholder}"

# Directory for "safe" files
FILES_DIR = '/tmp/ctf_files'
FLAG_FILE = '/tmp/flag.txt'


# ============================================================================
# SETUP
# ============================================================================
def setup_files():
    """Create the files directory and seed files."""
    os.makedirs(FILES_DIR, exist_ok=True)
    
    # Create some "safe" files
    with open(os.path.join(FILES_DIR, 'readme.txt'), 'w') as f:
        f.write('Welcome to the file server!')
    
    with open(os.path.join(FILES_DIR, 'info.txt'), 'w') as f:
        f.write('This is a sample file.')
    
    # Create the flag file OUTSIDE the safe directory
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
<head><title>File Server</title></head>
<body>
    <h1>File Server</h1>
    <p>Available files:</p>
    <ul>
        <li><a href="/files?name=readme.txt">readme.txt</a></li>
        <li><a href="/files?name=info.txt">info.txt</a></li>
    </ul>
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
setup_files()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
