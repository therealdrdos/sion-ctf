"""Base Flask template - minimal app for XSS and simple vulnerabilities."""

from flask import Flask, request, render_template_string

app = Flask(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================
# FLAG will be injected here
FLAG = "FLAG{placeholder}"


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
    <p>This is the home page.</p>
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
# RUN APP
# ============================================================================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
