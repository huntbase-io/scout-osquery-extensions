from flask import Flask, make_response, abort, jsonify
import os
import requests
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from flask_caching import Cache

# Configuration
USE_GITHUB = os.environ.get('USE_GITHUB', '0') == '1'
GITHUB_RAW_BASE_URL = "https://raw.githubusercontent.com/huntbase-io/scout-content/main"
ALLOWED_OS_DIRS = ["windows", "linux", "darwin"]

# Local directories (used when USE_GITHUB=0)
SCRIPTS_DIR = os.path.join(os.getcwd(), 'scripts')
BIN_DIR = os.path.join(os.getcwd(), 'bin')

app = Flask(__name__)

# Configure caching (mainly for GitHub fetching)
app.config['CACHE_TYPE'] = 'SimpleCache'  # for production consider Redis or Memcached
app.config['CACHE_DEFAULT_TIMEOUT'] = 300
cache = Cache(app)

# Load the private key
with open('private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
    )


# ---------- Helper Functions ----------
@cache.memoize(timeout=300)
def fetch_from_github(path):
    """
    Fetch content from GitHub raw URL. Returns content or None if not found.
    """
    url = f"{GITHUB_RAW_BASE_URL}/{path}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.content
    return None


def get_local_file_content(root_dir, filename):
    """
    Get content from a local file. Returns content or None if not found.
    """
    file_path = os.path.join(root_dir, filename)
    if not os.path.isfile(file_path):
        return None
    with open(file_path, 'rb') as f:
        return f.read()


def get_script_content(os_dir, filename):
    """
    Get script content either from GitHub or locally, depending on USE_GITHUB.
    If GitHub fails or USE_GITHUB=0, fallback to local if desired.
    """
    # Validate OS directory if provided
    if os_dir and os_dir not in ALLOWED_OS_DIRS:
        return None

    # Construct path
    if os_dir:
        path = f"scripts/{os_dir}/{filename}"
        local_path = os.path.join(SCRIPTS_DIR, os_dir, filename)
    else:
        path = f"scripts/{filename}"
        local_path = os.path.join(SCRIPTS_DIR, filename)

    content = None
    if USE_GITHUB:
        # Try to fetch from GitHub
        content = fetch_from_github(path)
        # If not found on GitHub, we could optionally fallback to local:
        # if content is None:
        #     content = get_local_file_content(os.path.join(SCRIPTS_DIR, os_dir) if os_dir else SCRIPTS_DIR, filename)
    else:
        # Local only
        content = get_local_file_content(os.path.join(SCRIPTS_DIR, os_dir) if os_dir else SCRIPTS_DIR, filename)

    return content


def get_bin_content(filename):
    """
    Get binary content either from GitHub or locally.
    """
    path = f"bin/{filename}"
    if USE_GITHUB:
        content = fetch_from_github(path)
        # If desired, fallback to local if GitHub not found:
        # if content is None:
        #     content = get_local_file_content(BIN_DIR, filename)
    else:
        content = get_local_file_content(BIN_DIR, filename)
    return content


def sign_content(content):
    """
    Sign the given content using the private key.
    """
    signature = private_key.sign(
        content,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature.hex()

def compute_hash(content):
    """
    Compute SHA256 hash of the content.
    """
    hasher = hashlib.sha256()
    hasher.update(content)
    return hasher.hexdigest()


# ---------- Routes ----------

@app.route('/bin/<path:filename>', methods=['GET'])
def serve_bin(filename):
    content = get_bin_content(filename)
    if content is None:
        abort(404, description="Binary not found")

    signature_hex = sign_content(content)
    response = make_response(content)
    response.headers['Content-Type'] = 'application/octet-stream'
    response.headers['X-Signature'] = signature_hex
    return response


@app.route('/scripts/<path:filename>', methods=['GET'])
def serve_script_no_os(filename):
    # This route is for scripts without OS directory specification
    content = get_script_content(None, filename)
    if content is None:
        abort(404, description="Script not found")

    signature_hex = sign_content(content)
    response = make_response(content)
    response.headers['Content-Type'] = 'application/octet-stream'
    response.headers['X-Signature'] = signature_hex
    return response


@app.route('/scripts/<os_dir>/<path:filename>', methods=['GET'])
def serve_script(os_dir, filename):
    # Validate OS directory and fetch the script
    content = get_script_content(os_dir, filename)
    if content is None:
        abort(404, description="Script not found")

    signature_hex = sign_content(content)
    response = make_response(content)
    response.headers['Content-Type'] = 'application/octet-stream'
    response.headers['X-Signature'] = signature_hex
    return response


@app.route('/scripts/hash/<path:filename>', methods=['GET'])
def get_script_hash_no_os(filename):
    content = get_script_content(None, filename)
    if content is None:
        abort(404, description="Script not found")

    script_hash = compute_hash(content)
    return jsonify({"script_hash": script_hash})


@app.route('/scripts/hash/<os_dir>/<path:filename>', methods=['GET'])
def get_script_hash(os_dir, filename):
    content = get_script_content(os_dir, filename)
    if content is None:
        abort(404, description="Script not found")

    script_hash = compute_hash(content)
    return jsonify({"script_hash": script_hash})


if __name__ == '__main__':
    # Run the app
    # Set the USE_GITHUB=1 environment variable before running if you want GitHub fetching
    # Example: USE_GITHUB=1 python unified_app.py
    app.run(host='127.0.0.1', port=5000)
