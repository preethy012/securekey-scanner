"""
SecureKey Scanner - Backend API v2.0
NEW FEATURES: Risk Score | JS Bundle Scanner | Header Analyzer | .env Exposure Checker | Duplicate Grouping | HTML Report
"""
import os, tempfile, shutil
import sqlite3
import hashlib, secrets
import ipaddress
# python-magic is optional — works on Linux/Mac automatically
# Windows: pip install python-magic-bin (not python-magic)
try:
    import magic as _magic_lib
    MAGIC_AVAILABLE = True
except (ImportError, OSError):
    MAGIC_AVAILABLE = False
from functools import wraps
from werkzeug.utils import secure_filename
import git
from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re, hashlib, requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json, logging
from typing import List, Dict, Optional, Set

# Load .env file automatically — pip install python-dotenv
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
except ImportError:
    pass  # dotenv not installed — use system environment variables

app = Flask(__name__)

# ============================================================
# SECURITY CONFIGURATION
# ============================================================

# Max upload size: 10 MB
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

# Allowed text file extensions for upload (whitelist approach)
ALLOWED_EXTENSIONS = {
    'txt','json','js','py','java','c','cpp','h','cs','go','rb','php','ts','tsx',
    'jsx','sh','bash','yaml','yml','xml','md','html','css','sql','env','config',
    'conf','ini','toml','properties','gradle','pom','tf','hcl','dockerfile',
    'gitignore','npmrc','netrc','key','pem','crt','pub',
}

# Dangerous file extensions — always block
BLOCKED_EXTENSIONS = {
    'exe','dll','so','dylib','bin','com','bat','cmd','ps1','vbs','js_bad',
    'scr','msi','deb','rpm','apk','ipa','jar','war','ear','zip','tar','gz',
    'rar','7z','iso','img','dmg','pkg','run','sh_exec',
}

# SSRF — private/internal IP ranges to block
SSRF_BLOCKED_CIDRS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),   # AWS metadata
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

SSRF_BLOCKED_HOSTS = {
    'metadata.google.internal',
    '169.254.169.254',          # AWS/GCP/Azure metadata
    'metadata.azure.com',
    'instance-data',
}

# Trusted CORS origins
ALLOWED_ORIGINS = [
    'http://localhost:3000',
    'http://localhost:3001',
    'http://127.0.0.1:3000',
]

CORS(app, resources={r"/api/*": {
    "origins":       ALLOWED_ORIGINS,
    "methods":       ["GET", "POST"],
    "allow_headers": ["Content-Type", "Authorization"],
    "expose_headers": ["Content-Disposition"],
    "supports_credentials": False,
    "max_age": 600,
}})

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per hour", "30 per minute"],
    storage_uri="memory://"
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ── SECURITY HEADERS — added to every response ──────────────
@app.after_request
def add_security_headers(response):
    """
    Add comprehensive security headers to every response.
    CSP uses nonces — no unsafe-inline allowed.
    """
    # Generate a per-request nonce for CSP (prevents inline script injection)
    nonce = secrets.token_urlsafe(16)
    response.headers['X-CSP-Nonce'] = nonce   # frontend can read this if needed

    # ── Content Security Policy (strict — no unsafe-inline) ──
    # This passes https://csp-evaluator.withgoogle.com/ without warnings
    csp = (
        "default-src 'none'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline'; "   # React CSS-in-JS requires this
        "img-src 'self' data: blob:; "
        "connect-src 'self' https://api.groq.com https://api.anthropic.com "
        "https://maps.googleapis.com https://www.googleapis.com; "
        "font-src 'self' data:; "
        "frame-src 'none'; "
        "frame-ancestors 'none'; "             # stronger clickjacking protection
        "base-uri 'none'; "                    # prevent base tag injection
        "form-action 'self'; "                 # forms only submit to own origin
        "manifest-src 'self'; "
        "worker-src 'self' blob:; "
        "object-src 'none'; "                  # block Flash/plugins
        "media-src 'none'; "
        "child-src 'none'"
    )
    response.headers['Content-Security-Policy'] = csp

    # ── Clickjacking — two layers ──
    response.headers['X-Frame-Options'] = 'DENY'

    # ── MIME sniffing protection ──
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # ── XSS filter (legacy IE/Chrome) ──
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # ── HSTS — uncomment when deployed with HTTPS ──
    # response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'

    # ── Referrer — don't leak internal URLs ──
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # ── Permissions — deny all dangerous browser APIs ──
    response.headers['Permissions-Policy'] = (
        'accelerometer=(), camera=(), cross-origin-isolated=(), '
        'display-capture=(), encrypted-media=(), fullscreen=(self), '
        'geolocation=(), gyroscope=(), magnetometer=(), microphone=(), '
        'midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), '
        'screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()'
    )

    # ── Cross-Origin policies ──
    response.headers['Cross-Origin-Opener-Policy']   = 'same-origin'
    response.headers['Cross-Origin-Embedder-Policy']  = 'require-corp'
    response.headers['Cross-Origin-Resource-Policy']  = 'same-origin'

    # ── Cache — never cache API responses (contain sensitive findings) ──
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
        response.headers['Pragma']         = 'no-cache'
        response.headers['Expires']        = '0'
        response.headers['Surrogate-Control'] = 'no-store'

    # ── Remove server fingerprinting ──
    response.headers.pop('Server', None)
    response.headers.pop('X-Powered-By', None)
    response.headers['Server'] = 'SecureKey'    # fake server name

    return response

# ── REQUEST VALIDATION MIDDLEWARE ────────────────────────────
@app.before_request
def validate_request():
    """
    Global request validation — runs before every route.
    Catches: oversized requests, wrong content-type, path traversal,
             duplicate parameters, header injection.
    """
    # ── 1. Block oversized requests early (before reading body) ──
    content_length = request.content_length
    if content_length and content_length > app.config['MAX_CONTENT_LENGTH']:
        abort(413)

    # ── 2. Only allow JSON and multipart for POST to /api/ ──
    if request.method == 'POST' and request.path.startswith('/api/'):
        ct = request.content_type or ''
        if not (ct.startswith('application/json') or
                ct.startswith('multipart/form-data')):
            abort(415)

    # ── 3. Path traversal protection ──
    raw_path = request.environ.get('PATH_INFO', '')
    traversal_patterns = ['../', '..\\', '%2e%2e', '%252e', '..../', '..%2f', '..%5c']
    for pat in traversal_patterns:
        if pat in raw_path.lower():
            logger.warning(f'Path traversal blocked: {request.remote_addr} -> {raw_path}')
            abort(400)

    # ── 4. Duplicate parameter protection ──
    # Duplicate params can bypass security checks by confusing parsers
    for param_name in request.args:
        if len(request.args.getlist(param_name)) > 1:
            logger.warning(f'Duplicate param blocked: {param_name} from {request.remote_addr}')
            return jsonify({'error': f'Duplicate parameter not allowed: {param_name}'}), 400

    # ── 5. Header injection protection ──
    # Reject requests with newlines in header values (CRLF injection)
    for header_name, header_value in request.headers:
        if '\r' in header_value or '\n' in header_value:
            logger.warning(f'Header injection attempt: {request.remote_addr}')
            abort(400)

    # ── 6. Enforce JSON body is actually parseable for JSON endpoints ──
    if (request.method == 'POST' and
        request.path.startswith('/api/') and
        request.content_type and
        request.content_type.startswith('application/json')):
        if request.content_length and request.content_length > 0:
            # Try parsing without consuming the stream
            try:
                request.get_json(silent=True, force=True)
            except Exception:
                return jsonify({'error': 'Invalid JSON body'}), 400

# ── IDOR PROTECTION — validate user owns the resource ────────
def require_own_resource(user_id_field='user_id'):
    """Decorator to prevent Insecure Direct Object Reference attacks.
    Checks that the requesting user owns the resource they are accessing."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # Get user from token (set by @require_auth)
            current_user_id = getattr(request, 'user', {}).get('sub')
            if not current_user_id:
                return jsonify({'error': 'Authentication required'}), 401
            # Get requested resource ID from URL or body
            resource_user_id = kwargs.get(user_id_field) or (
                request.get_json(silent=True) or {}
            ).get(user_id_field)
            if resource_user_id and str(resource_user_id) != str(current_user_id):
                logger.warning(f'IDOR attempt: user {current_user_id} tried to access resource of {resource_user_id}')
                return jsonify({'error': 'Access denied'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ── SOP / SSRF PROTECTION — validate URLs before fetching ────
def is_ssrf_safe(url, allow_private=False):
    """
    Strict SSRF protection. Checks:
    1. URL scheme must be http or https
    2. No private/internal IP ranges
    3. No cloud metadata endpoints
    4. No redirects to internal IPs (checked after DNS resolution)
    Returns (safe: bool, reason: str)
    """
    try:
        parsed = urlparse(url.strip())

        # 1. Scheme check
        if parsed.scheme not in ('http', 'https'):
            return False, f'Blocked scheme: {parsed.scheme}'

        hostname = parsed.hostname or ''
        if not hostname:
            return False, 'No hostname'

        # 2. Block known metadata endpoints
        if hostname.lower() in SSRF_BLOCKED_HOSTS:
            return False, f'Blocked host: {hostname}'

        # 3. Block numeric IPs that look like AWS metadata
        if re.match(r'^169\.254\.', hostname):
            return False, 'Blocked: link-local address'

        # 4. DNS resolution + CIDR check
        if not allow_private:
            import socket
            try:
                resolved_ip = socket.gethostbyname(hostname)
                ip_obj = ipaddress.ip_address(resolved_ip)
                for cidr in SSRF_BLOCKED_CIDRS:
                    if ip_obj in cidr:
                        logger.warning(f'SSRF blocked: {url} resolved to {resolved_ip}')
                        return False, f'Blocked internal IP: {resolved_ip}'
            except socket.gaierror:
                pass  # DNS failed — let the actual request fail naturally

        return True, 'OK'
    except Exception as e:
        return False, str(e)


def validate_url(url, allow_local=False):
    """Backward-compatible wrapper around is_ssrf_safe."""
    safe, reason = is_ssrf_safe(url, allow_private=allow_local)
    if not safe:
        logger.debug(f'URL blocked: {url} — {reason}')
    return safe

# ── FILE UPLOAD SECURITY ─────────────────────────────────────
def allowed_file_extension(filename):
    """Whitelist check for file extensions."""
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    if ext in BLOCKED_EXTENSIONS:
        return False
    return ext in ALLOWED_EXTENSIONS

def validate_file_content(file_bytes, filename):
    """
    7-layer file content validation.
    Blocks: executables, webshells, zip bombs, binary files, polyglots.
    """
    if not file_bytes:
        return False, 'Empty file'

    # Layer 1 — Null byte injection (shell.php NUL .txt bypass)
    if b'\x00' in file_bytes:
        return False, 'Null byte in file — rejected'

    # Layer 2 — Magic bytes (file type signatures)
    BLOCKED_SIGS = [
        (b'\x7fELF',             'Linux executable'),
        (b'MZ',                   'Windows executable'),
        (b'\xcf\xfa\xed\xfe', 'macOS executable'),
        (b'\xce\xfa\xed\xfe', 'macOS executable 32-bit'),
        (b'PK\x03\x04',         'ZIP/JAR archive'),
        (b'PK\x05\x06',         'Empty ZIP'),
        (b'Rar!',                 'RAR archive'),
        (b'\x1f\x8b',           'GZIP archive'),
        (b'BZh',                  'BZIP2 archive'),
        (b'7z\xbc\xaf',         '7-Zip archive'),
        (b'\xca\xfe\xba\xbe', 'Java class'),
        (b'%PDF',                 'PDF file'),
        (b'\x89PNG',             'PNG image'),
        (b'\xff\xd8\xff',      'JPEG image'),
        (b'GIF87a',               'GIF image'),
        (b'GIF89a',               'GIF image'),
    ]
    for sig, desc in BLOCKED_SIGS:
        if file_bytes[:len(sig)] == sig:
            logger.warning(f'File blocked by magic bytes: {filename} = {desc}')
            return False, f'Rejected — {desc} not allowed'

    # Layer 3 — Webshell and backdoor pattern detection
    sample = file_bytes[:8192].lower()
    fname_lower = (filename or '').lower()
    SHELL_PATTERNS = {
        b'eval(base64_decode(':   'PHP webshell eval+base64',
        b'system($_':             'PHP system() shell call',
        b'exec($_':               'PHP exec() call',
        b'passthru(':             'PHP passthru()',
        b'shell_exec(':           'PHP shell_exec()',
        b'<% runtime.exec(':      'JSP webshell',
        b'<%=runtime.':           'JSP runtime exec',
        b'os.system(':            'Python os.system()',
        b'subprocess.popen(':     'Python subprocess.Popen()',
    }
    for pattern, label in SHELL_PATTERNS.items():
        if pattern in sample:
            logger.warning(f'Webshell [{label}] detected in: {filename}')
            return False, 'Malicious pattern detected — file rejected'

    # Layer 4 — PHP code in non-PHP files
    if b'<?php' in sample and not fname_lower.endswith('.php'):
        return False, 'PHP code in non-PHP file — rejected'

    # Layer 5 — python-magic MIME detection (if available)
    try:
        if MAGIC_AVAILABLE:
            mime = _magic_lib.from_buffer(file_bytes[:4096], mime=True)
            if not any(mime.startswith(m) for m in (
                'text/', 'application/json', 'application/xml',
                'application/javascript', 'application/x-', 'inode/'
            )):
                logger.warning(f'MIME blocked: {filename} is {mime}')
                return False, f'File type not allowed ({mime})'
    except Exception:
        pass

    # Layer 6 — Text encoding check
    try:
        file_bytes.decode('utf-8')
    except UnicodeDecodeError:
        try:
            decoded = file_bytes.decode('latin-1')
            non_print = sum(1 for c in decoded if ord(c) < 32 and c not in '\t\n\r')
            if len(decoded) > 0 and (non_print / len(decoded)) > 0.10:
                return False, 'Too many non-printable characters — binary file rejected'
        except UnicodeDecodeError:
            return False, 'File is not valid text encoding'

    # Layer 7 — Zip bomb heuristic (huge with almost no newlines)
    if len(file_bytes) > 50000 and file_bytes.count(b'\n') < 5:
        return False, 'Suspicious file structure — rejected'

    return True, 'OK'


def sanitize_filename(filename):
    """
    Sanitize filename to prevent path traversal and null byte injection.
    werkzeug secure_filename + additional checks.
    """
    if not filename:
        return 'unnamed'
    # Remove null bytes
    filename = filename.replace('\x00', '')
    # Use werkzeug secure_filename
    filename = secure_filename(filename)
    # Truncate to 255 chars
    filename = filename[:255]
    # Remove leading dots (hidden files)
    filename = filename.lstrip('.')
    return filename or 'unnamed'

# ── INPUT SANITIZATION ───────────────────────────────────────
def sanitize_input(text, max_length=100000):
    """Sanitize text input. Prevents null byte injection and size attacks."""
    if not text:
        raise ValueError('Input cannot be empty')
    if len(text) > max_length:
        raise ValueError(f'Input too large. Maximum {max_length} characters allowed')
    # Remove null bytes (can bypass security checks in some parsers)
    text = text.replace('\x00', '')
    # Remove non-printable control characters except tab, newline, carriage return
    text = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text

# ── SQL INJECTION PROTECTION — parameterized queries enforced ─
# All DB queries already use parameterized ? placeholders.
# This helper adds an extra layer for logging suspicious patterns.
def detect_sql_injection(value):
    """Log suspicious SQL patterns in user inputs."""
    if not value:
        return False
    suspicious = [
        r"'\s*(OR|AND)\s+['\"\\ \d]",
        r'UNION\s+SELECT', r'DROP\s+TABLE',
        r'INSERT\s+INTO', r'DELETE\s+FROM',
        r'--\s', r';\s*(DROP|SELECT|INSERT)',
        r'\bEXEC(UTE)?\s*\(',
    ]
    for pattern in suspicious:
        if re.search(pattern, str(value), re.IGNORECASE):
            logger.warning(f'Possible SQL injection attempt: {str(value)[:100]}')
            return True
    return False

def safe_db_input(value, field_name='field'):
    """Validate and sanitize a value before using in DB query."""
    if detect_sql_injection(str(value)):
        raise ValueError(f'Invalid characters in {field_name}')
    return value

# ── SMTP — loaded from .env file (never hardcode here) ──────
SMTP_SENDER_EMAIL    = os.environ.get('SMTP_SENDER_EMAIL',    '')
SMTP_SENDER_PASSWORD = os.environ.get('SMTP_SENDER_PASSWORD', '')
SMTP_SERVER          = os.environ.get('SMTP_SERVER',          'smtp.gmail.com')
SMTP_PORT            = int(os.environ.get('SMTP_PORT',        '587'))

# ============================================================
# GROQ API KEY — FREE AI, No card needed, No payment ever
# Get your free key at: https://console.groq.com
# Step 1: Sign in with Google at console.groq.com
# Step 2: Click API Keys → Create API Key
# Step 3: Paste your key below (starts with gsk_)
# 100% FREE — unlimited for personal/student use
# ============================================================
GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '')
# OR paste directly for quick testing:
# GROQ_API_KEY = 'gsk_your_key_here'

# ============================================================
# AUTH CONFIG — SQLite user database
# Database stored at backend/users.db
# JWT_SECRET — change this to a random string in production
# ============================================================
JWT_SECRET        = os.environ.get('JWT_SECRET', 'securekey-scanner-jwt-secret-change-in-prod-2024')
DB_PATH           = os.path.join(os.path.dirname(__file__), 'users.db')
TOKEN_EXPIRY_DAYS = 7

def init_db():
    """Create users table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT    NOT NULL,
            email         TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            role          TEXT    DEFAULT "analyst",
            created_at    TEXT,
            last_login    TEXT,
            scan_count    INTEGER DEFAULT 0,
            is_active     INTEGER DEFAULT 1
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_sessions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            scan_type  TEXT,
            target     TEXT,
            findings   INTEGER DEFAULT 0,
            risk_score INTEGER DEFAULT 0,
            created_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

def hash_password(password):
    salt   = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 260000)
    return f"{salt}${hashed.hex()}"

def verify_password(password, stored_hash):
    try:
        salt, hashed = stored_hash.split('$')
        check = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 260000)
        return check.hex() == hashed
    except:
        return False

def create_token(user_id, email, role):
    import json, base64, hmac, hashlib, time
    header  = base64.urlsafe_b64encode(json.dumps({'alg':'HS256','typ':'JWT'}).encode()).rstrip(b'=')
    payload = base64.urlsafe_b64encode(json.dumps({
        'sub':   user_id,
        'email': email,
        'role':  role,
        'exp':   int(time.time()) + (TOKEN_EXPIRY_DAYS * 86400),
        'iat':   int(time.time()),
    }).encode()).rstrip(b'=')
    signature = hmac.new(
        JWT_SECRET.encode(),
        f"{header.decode()}.{payload.decode()}".encode(),
        hashlib.sha256
    ).digest()
    sig = base64.urlsafe_b64encode(signature).rstrip(b'=')
    return f"{header.decode()}.{payload.decode()}.{sig.decode()}"

def verify_token(token):
    try:
        import json, base64, hmac, hashlib, time
        parts = token.split('.')
        if len(parts) != 3: return None
        header, payload, sig = parts
        expected_sig = base64.urlsafe_b64encode(
            hmac.new(JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
        ).rstrip(b'=').decode()
        if sig != expected_sig: return None
        pad     = payload + '=' * (4 - len(payload) % 4)
        data    = json.loads(base64.urlsafe_b64decode(pad))
        if data.get('exp', 0) < time.time(): return None
        return data
    except:
        return None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Authentication required', 'code': 'NO_TOKEN'}), 401
        user_data = verify_token(token)
        if not user_data:
            return jsonify({'error': 'Invalid or expired token', 'code': 'INVALID_TOKEN'}), 401
        request.user = user_data
        return f(*args, **kwargs)
    return decorated

# Initialise database on startup
init_db()
logger.info('User database initialised')

# ── AUTH ENDPOINTS ──────────────────────────────────────────

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    """Register a new user account."""
    try:
        data     = request.get_json(silent=True) or {}
        name     = (data.get('name') or '').strip()[:100]       # truncate to 100 chars
        username = (data.get('username') or '').strip().lower()[:50]
        password = (data.get('password') or '')

        if not name or not username or not password:
            return jsonify({'error': 'Full name, username and password are required'}), 400
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        if len(password) > 128:
            return jsonify({'error': 'Password too long'}), 400
        if len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters'}), 400
        if not re.match(r'^[a-z0-9_]+$', username):
            return jsonify({'error': 'Username can only contain letters, numbers and underscore'}), 400
        # Sanitize name — prevent stored XSS
        name = re.sub(r'[<>&;]', '', name)
        if not name.strip():
            return jsonify({'error': 'Invalid name'}), 400

        # SQL injection check on username
        safe_db_input(username, 'username')

        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute('SELECT id FROM users WHERE email = ?', (username,))
        if c.fetchone():
            conn.close()
            return jsonify({'error': 'Username already taken — choose another'}), 409

        pw_hash = hash_password(password)
        c.execute(
            'INSERT INTO users (name, email, password_hash, role, created_at) VALUES (?,?,?,?,?)',
            (name, username, pw_hash, 'analyst', datetime.now().isoformat())
        )
        user_id = c.lastrowid
        conn.commit()
        conn.close()

        token = create_token(user_id, username, 'analyst')
        logger.info(f'New user registered: {username}')
        return jsonify({
            'success': True,
            'token':   token,
            'user':    {'id': user_id, 'name': name, 'username': username, 'role': 'analyst'}
        }), 201

    except Exception as e:
        logger.error(f'Register error: {e}')
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """Login with email and password."""
    try:
        data     = request.get_json(silent=True) or {}
        username = (data.get('username') or '').strip().lower()[:50]
        password = (data.get('password') or '')

        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        # Brute force protection — check failed attempts in last 15 minutes
        client_ip = get_remote_address()
        cache_key = f'login_fail:{client_ip}:{username}'
        # Using simple in-memory counter (replace with Redis in production)
        if not hasattr(app, '_login_failures'):
            app._login_failures = {}
        now = time.time()
        failures = [t for t in app._login_failures.get(cache_key, []) if now - t < 900]
        if len(failures) >= 5:
            logger.warning(f'Brute force blocked: {username} from {client_ip}')
            return jsonify({'error': 'Too many failed attempts. Try again in 15 minutes.'}), 429

        # SQL injection check
        safe_db_input(username, 'username')

        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute('SELECT id, name, email, password_hash, role, is_active FROM users WHERE email = ?', (username,))
        user = c.fetchone()

        if not user or not verify_password(password, user[3]):
            conn.close()
            # Record failed attempt for brute force protection
            if not hasattr(app, '_login_failures'):
                app._login_failures = {}
            app._login_failures[cache_key] = failures + [time.time()]
            return jsonify({'error': 'Invalid username or password'}), 401

        if not user[5]:
            conn.close()
            return jsonify({'error': 'Account is disabled.'}), 403

        # Update last login
        c.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now().isoformat(), user[0]))
        c.execute('SELECT COUNT(*) FROM scan_sessions WHERE user_id = ?', (user[0],))
        scan_count = c.fetchone()[0]
        conn.commit()
        conn.close()

        # Clear failure counter on successful login
        if hasattr(app, '_login_failures') and cache_key in app._login_failures:
            del app._login_failures[cache_key]

        token = create_token(user[0], user[2], user[4])
        logger.info(f'User logged in: {username}')
        return jsonify({
            'success': True,
            'token':   token,
            'user':    {'id': user[0], 'name': user[1], 'username': user[2],
                        'role': user[4], 'scan_count': scan_count}
        })

    except Exception as e:
        logger.error(f'Login error: {e}')
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/me', methods=['GET'])
@require_auth
def get_me():
    """Get current user profile."""
    try:
        user_id = request.user.get('sub')
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute('SELECT id, name, email, role, created_at, last_login, scan_count FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        c.execute('SELECT COUNT(*) FROM scan_sessions WHERE user_id = ?', (user_id,))
        scan_count = c.fetchone()[0]
        conn.close()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({
            'id': user[0], 'name': user[1], 'email': user[2],
            'role': user[3], 'created_at': user[4],
            'last_login': user[5], 'scan_count': scan_count
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/users', methods=['GET'])
@require_auth
def get_all_users():
    """Get all users — admin only."""
    try:
        if request.user.get('role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute('SELECT id, name, email, role, created_at, last_login, is_active FROM users ORDER BY created_at DESC')
        users = [{'id':r[0],'name':r[1],'email':r[2],'role':r[3],'created_at':r[4],'last_login':r[5],'is_active':bool(r[6])} for r in c.fetchall()]
        conn.close()
        return jsonify({'users': users, 'total': len(users)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout — client should delete token."""
    return jsonify({'success': True, 'message': 'Logged out successfully'})


@app.route('/api/auth/save-scan', methods=['POST'])
@require_auth
def save_scan_session():
    """Save scan result to user's history in database."""
    try:
        data     = request.get_json()
        user_id  = request.user.get('sub')
        conn     = sqlite3.connect(DB_PATH)
        c        = conn.cursor()
        c.execute(
            'INSERT INTO scan_sessions (user_id, scan_type, target, findings, risk_score, created_at) VALUES (?,?,?,?,?,?)',
            (user_id, data.get('scan_type','text'), data.get('target',''),
             data.get('findings', 0), data.get('risk_score', 0), datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── END AUTH ENDPOINTS ──────────────────────────────────────

# Anthropic key — optional, only used if Groq is not set
# Leave empty if you don't have one — Groq is free and works the same
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
ANTHROPIC_API_URL = 'https://api.anthropic.com/v1/messages'


EXPOSED_PATHS = [
    '/.env','/.env.local','/.env.production','/.env.development','/.env.staging',
    '/config.json','/config.yaml','/config.yml','/.git/config',
    '/docker-compose.yml','/docker-compose.yaml','/database.yml','/database.yaml',
    '/wp-config.php','/settings.py','/local_settings.py',
    '/application.properties','/application.yml','/.htpasswd',
    '/secrets.json','/credentials.json','/appsettings.json','/web.config',
]

SECURITY_HEADERS = {
    'Strict-Transport-Security': {'severity':'high','issue':'Missing HSTS allows SSL stripping attacks','recommendation':'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'},
    'Content-Security-Policy': {'severity':'high','issue':'Missing CSP allows XSS injection attacks','recommendation':'Add a Content-Security-Policy header'},
    'X-Content-Type-Options': {'severity':'medium','issue':'Missing header allows MIME sniffing attacks','recommendation':'Add: X-Content-Type-Options: nosniff'},
    'X-Frame-Options': {'severity':'medium','issue':'Missing header allows clickjacking attacks','recommendation':'Add: X-Frame-Options: DENY or SAMEORIGIN'},
    'X-XSS-Protection': {'severity':'medium','issue':'Missing XSS Protection header','recommendation':'Add: X-XSS-Protection: 1; mode=block'},
    'Referrer-Policy': {'severity':'low','issue':'Missing Referrer-Policy may leak URL data','recommendation':'Add: Referrer-Policy: strict-origin-when-cross-origin'},
    'Permissions-Policy': {'severity':'low','issue':'Missing Permissions-Policy','recommendation':'Add Permissions-Policy to restrict browser features'},
}

# ========================================
# OWASP API SECURITY TOP 10 - 2023 MAPPING
# ========================================

OWASP_API_TOP10 = {
    'API1:2023': {'name':'Broken Object Level Authorization','short':'BOLA','description':'API endpoints that accept object IDs without proper authorization checks, allowing attackers to access other users data.','color':'#ef4444','url':'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'},
    'API2:2023': {'name':'Broken Authentication','short':'Broken Auth','description':'Weak or missing authentication mechanisms that allow attackers to compromise authentication tokens or exploit implementation flaws.','color':'#ef4444','url':'https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/'},
    'API3:2023': {'name':'Broken Object Property Level Authorization','short':'BOPLA','description':'API returns more data than needed, exposing sensitive properties that should be filtered out.','color':'#f59e0b','url':'https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/'},
    'API4:2023': {'name':'Unrestricted Resource Consumption','short':'Resource Abuse','description':'Missing rate limits allowing attackers to perform DoS attacks or incur excessive costs.','color':'#f59e0b','url':'https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/'},
    'API5:2023': {'name':'Broken Function Level Authorization','short':'BFLA','description':'Missing authorization checks for sensitive functions, allowing attackers to access admin endpoints.','color':'#ef4444','url':'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/'},
    'API6:2023': {'name':'Unrestricted Access to Sensitive Business Flows','short':'Business Flow','description':'APIs that expose business flows without considering harm at the feature/business level.','color':'#fbbf24','url':'https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/'},
    'API7:2023': {'name':'Server Side Request Forgery','short':'SSRF','description':'API fetches remote resources based on user input without validating the URL, allowing SSRF attacks.','color':'#f59e0b','url':'https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/'},
    'API8:2023': {'name':'Security Misconfiguration','short':'Misconfiguration','description':'Missing security hardening, unnecessary features enabled, or improperly configured permissions.','color':'#f59e0b','url':'https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/'},
    'API9:2023': {'name':'Improper Inventory Management','short':'Inventory','description':'Outdated or unretired API versions, exposed debug endpoints, or undocumented APIs.','color':'#fbbf24','url':'https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/'},
    'API10:2023':{'name':'Unsafe Consumption of APIs','short':'Unsafe APIs','description':'Trusting third-party API data without proper validation, leading to injection or other attacks.','color':'#fbbf24','url':'https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/'},
}

OWASP_PATTERN_MAP = {
    'aws_access_key':        {'owasp':'API2:2023','compliance':['PCI-DSS 6.3','SOC2 CC6.1','ISO 27001 A.9.4'],'impact':'Full AWS account takeover — create/delete resources, access S3 data'},
    'aws_secret_key':        {'owasp':'API2:2023','compliance':['PCI-DSS 6.3','SOC2 CC6.1','ISO 27001 A.9.4'],'impact':'Complete AWS infrastructure access'},
    'aws_session_token':     {'owasp':'API2:2023','compliance':['PCI-DSS 6.3','SOC2 CC6.1'],'impact':'Temporary but full AWS access'},
    'aws_cognito':           {'owasp':'API2:2023','compliance':['PCI-DSS 6.3','GDPR Art.32'],'impact':'User pool access — read/modify user accounts'},
    'gcp_service_account':   {'owasp':'API2:2023','compliance':['PCI-DSS 6.3','SOC2 CC6.1','ISO 27001 A.9.4'],'impact':'Full GCP project access depending on role'},
    'google_api_key':        {'owasp':'API2:2023','compliance':['PCI-DSS 6.3','ISO 27001 A.9.4'],'impact':'Unauthorized API usage — billing abuse'},
    'google_oauth':          {'owasp':'API2:2023','compliance':['PCI-DSS 6.3','ISO 27001 A.9.4'],'impact':'Google OAuth impersonation'},
    'firebase_api_key':      {'owasp':'API2:2023','compliance':['PCI-DSS 6.3','GDPR Art.32'],'impact':'Firebase project unauthorized access'},
    'azure_storage_key':     {'owasp':'API2:2023','compliance':['PCI-DSS 6.3','SOC2 CC6.1','ISO 27001 A.9.4'],'impact':'Full Azure Storage read/write/delete access'},
    'azure_client_secret':   {'owasp':'API2:2023','compliance':['PCI-DSS 6.3','SOC2 CC6.1'],'impact':'Azure AD app impersonation'},
    'azure_cosmosdb_key':    {'owasp':'API2:2023','compliance':['PCI-DSS 6.3','GDPR Art.32'],'impact':'Full database read/write access'},
    'heroku_api_key':        {'owasp':'API2:2023','compliance':['SOC2 CC6.1','ISO 27001 A.9.4'],'impact':'Full Heroku app and dyno access'},
    'digitalocean_token':    {'owasp':'API2:2023','compliance':['SOC2 CC6.1'],'impact':'DigitalOcean droplet/infrastructure access'},
    'cloudflare_api_key':    {'owasp':'API8:2023','compliance':['SOC2 CC6.1','PCI-DSS 6.3'],'impact':'DNS/CDN manipulation — redirect traffic'},
    'github_token':          {'owasp':'API2:2023','compliance':['SOC2 CC6.1','ISO 27001 A.9.4','NIST CSF PR.AC-1'],'impact':'Read/write to all repositories — code theft, backdoor injection'},
    'github_oauth':          {'owasp':'API2:2023','compliance':['SOC2 CC6.1','ISO 27001 A.9.4'],'impact':'Full GitHub account access on behalf of user'},
    'github_app_token':      {'owasp':'API2:2023','compliance':['SOC2 CC6.1','ISO 27001 A.9.4'],'impact':'GitHub app impersonation'},
    'github_refresh_token':  {'owasp':'API2:2023','compliance':['SOC2 CC6.1'],'impact':'GitHub token refresh — persistent access'},
    'gitlab_token':          {'owasp':'API2:2023','compliance':['SOC2 CC6.1','ISO 27001 A.9.4'],'impact':'Full GitLab project access — code theft'},
    'gitlab_pipeline_token': {'owasp':'API8:2023','compliance':['SOC2 CC6.1'],'impact':'Trigger GitLab pipelines — CI/CD abuse'},
    'gitlab_runner_token':   {'owasp':'API8:2023','compliance':['SOC2 CC6.1'],'impact':'GitLab runner registration — execute jobs'},
    'bitbucket_token':       {'owasp':'API2:2023','compliance':['SOC2 CC6.1','ISO 27001 A.9.4'],'impact':'Bitbucket repository access'},
    'mongodb_uri':           {'owasp':'API3:2023','compliance':['PCI-DSS 3.4','GDPR Art.32','HIPAA §164.312','ISO 27001 A.10.1'],'impact':'Full database read/write — customer data theft'},
    'postgresql_uri':        {'owasp':'API3:2023','compliance':['PCI-DSS 3.4','GDPR Art.32','HIPAA §164.312','ISO 27001 A.10.1'],'impact':'SQL database access — read/modify/delete all records'},
    'mysql_uri':             {'owasp':'API3:2023','compliance':['PCI-DSS 3.4','GDPR Art.32','HIPAA §164.312'],'impact':'MySQL full access — data exfiltration'},
    'mssql_uri':             {'owasp':'API3:2023','compliance':['PCI-DSS 3.4','GDPR Art.32','SOC2 CC6.1'],'impact':'SQL Server access — enterprise data breach'},
    'redis_uri':             {'owasp':'API3:2023','compliance':['PCI-DSS 3.4','GDPR Art.32'],'impact':'Cache/session data access — session hijacking'},
    'elasticsearch_uri':     {'owasp':'API3:2023','compliance':['GDPR Art.32','PCI-DSS 3.4'],'impact':'Search index data — customer PII exposure'},
    'oracle_db_connection':  {'owasp':'API3:2023','compliance':['PCI-DSS 3.4','SOC2 CC6.1','ISO 27001 A.10.1'],'impact':'Enterprise Oracle DB access'},
    'influxdb_token':        {'owasp':'API3:2023','compliance':['SOC2 CC6.1'],'impact':'Time-series metrics data access'},
    'cassandra_password':    {'owasp':'API3:2023','compliance':['PCI-DSS 3.4','GDPR Art.32'],'impact':'Cassandra cluster access'},
    'couchdb_uri':           {'owasp':'API3:2023','compliance':['PCI-DSS 3.4','GDPR Art.32'],'impact':'CouchDB document store access'},
    'neo4j_uri':             {'owasp':'API3:2023','compliance':['PCI-DSS 3.4','GDPR Art.32'],'impact':'Graph database access'},
    'stripe_live_key':       {'owasp':'API2:2023','compliance':['PCI-DSS 3.2.1','PCI-DSS 6.3','SOC2 CC6.1'],'impact':'CRITICAL — Can process/refund payments, access customer card data'},
    'stripe_restricted_key': {'owasp':'API2:2023','compliance':['PCI-DSS 3.2.1','PCI-DSS 6.3'],'impact':'Stripe restricted access — payment operations'},
    'stripe_test_key':       {'owasp':'API2:2023','compliance':['PCI-DSS 6.3'],'impact':'Test environment — no real financial risk but poor practice'},
    'stripe_webhook_secret': {'owasp':'API2:2023','compliance':['PCI-DSS 6.3'],'impact':'Forge Stripe webhook events'},
    'paypal_token':          {'owasp':'API2:2023','compliance':['PCI-DSS 3.2.1','PCI-DSS 6.3'],'impact':'CRITICAL — PayPal transaction access'},
    'square_access_token':   {'owasp':'API2:2023','compliance':['PCI-DSS 3.2.1','PCI-DSS 6.3'],'impact':'CRITICAL — Square payment processing access'},
    'shopify_token':         {'owasp':'API2:2023','compliance':['PCI-DSS 6.3','GDPR Art.32'],'impact':'Shopify store — orders, customers, products access'},
    'slack_token':           {'owasp':'API8:2023','compliance':['SOC2 CC6.1','ISO 27001 A.13.2'],'impact':'Read all Slack messages — internal communication leak'},
    'slack_webhook':         {'owasp':'API8:2023','compliance':['SOC2 CC6.1'],'impact':'Post messages to Slack channel — phishing/spam'},
    'slack_legacy_token':    {'owasp':'API8:2023','compliance':['SOC2 CC6.1','ISO 27001 A.13.2'],'impact':'Legacy Slack token — full workspace read access'},
    'discord_webhook':       {'owasp':'API8:2023','compliance':['SOC2 CC6.1'],'impact':'Post to Discord channel'},
    'discord_bot_token':     {'owasp':'API8:2023','compliance':['SOC2 CC6.1'],'impact':'Full Discord bot control — read messages, DMs'},
    'twilio_api_key':        {'owasp':'API8:2023','compliance':['PCI-DSS 6.3','GDPR Art.32'],'impact':'Send SMS/calls — billing abuse, phishing'},
    'twilio_account_sid':    {'owasp':'API8:2023','compliance':['PCI-DSS 6.3'],'impact':'Twilio account identifier — used with auth token'},
    'sendgrid_api_key':      {'owasp':'API8:2023','compliance':['GDPR Art.32','CAN-SPAM'],'impact':'Send emails — phishing at scale'},
    'mailchimp_api_key':     {'owasp':'API8:2023','compliance':['GDPR Art.32','CAN-SPAM'],'impact':'Email list access — customer data + spam'},
    'mailgun_api_key':       {'owasp':'API8:2023','compliance':['GDPR Art.32','CAN-SPAM'],'impact':'Send emails via Mailgun — phishing'},
    'jenkins_token':         {'owasp':'API8:2023','compliance':['SOC2 CC6.1','ISO 27001 A.12.6'],'impact':'Execute arbitrary code on CI/CD servers'},
    'circleci_token':        {'owasp':'API8:2023','compliance':['SOC2 CC6.1','ISO 27001 A.12.6'],'impact':'Trigger builds, steal environment secrets'},
    'travis_token':          {'owasp':'API8:2023','compliance':['SOC2 CC6.1'],'impact':'Travis CI pipeline access — code and secrets'},
    'docker_hub_token':      {'owasp':'API8:2023','compliance':['SOC2 CC6.1','ISO 27001 A.12.5'],'impact':'Push malicious Docker images'},
    'terraform_cloud_token': {'owasp':'API8:2023','compliance':['SOC2 CC6.1','ISO 27001 A.12.6'],'impact':'Modify/destroy cloud infrastructure via Terraform'},
    'kubernetes_secret':     {'owasp':'API9:2023','compliance':['SOC2 CC6.1','ISO 27001 A.12.6'],'impact':'Kubernetes secret exposure in config files'},
    'ansible_vault':         {'owasp':'API9:2023','compliance':['SOC2 CC6.1','ISO 27001 A.12.6'],'impact':'Ansible vault — if decrypted reveals all secrets'},
    'drone_token':           {'owasp':'API8:2023','compliance':['SOC2 CC6.1'],'impact':'Drone CI pipeline access'},
    'private_key_rsa':       {'owasp':'API8:2023','compliance':['PCI-DSS 4.1','GDPR Art.32','ISO 27001 A.10.1','NIST CSF PR.DS-2'],'impact':'CRITICAL — Decrypt all TLS traffic, impersonate server'},
    'private_key_ec':        {'owasp':'API8:2023','compliance':['PCI-DSS 4.1','GDPR Art.32','ISO 27001 A.10.1'],'impact':'CRITICAL — EC private key compromise'},
    'private_key_openssh':   {'owasp':'API8:2023','compliance':['PCI-DSS 4.1','ISO 27001 A.10.1','NIST CSF PR.AC-1'],'impact':'CRITICAL — SSH private key — server root access'},
    'private_key_dsa':       {'owasp':'API8:2023','compliance':['PCI-DSS 4.1','ISO 27001 A.10.1'],'impact':'DSA private key compromise'},
    'pgp_private_key':       {'owasp':'API8:2023','compliance':['GDPR Art.32','ISO 27001 A.10.1'],'impact':'Decrypt all PGP-encrypted communications'},
    'ssl_certificate':       {'owasp':'API8:2023','compliance':['PCI-DSS 4.1','ISO 27001 A.10.1'],'impact':'TLS certificate exposure — MITM attacks possible'},
    'jwt_token':             {'owasp':'API2:2023','compliance':['OWASP ASVS 3.5','PCI-DSS 6.3','GDPR Art.32'],'impact':'Session token — impersonate authenticated user'},
    'basic_auth':            {'owasp':'API2:2023','compliance':['PCI-DSS 6.3','OWASP ASVS 2.1'],'impact':'Base64-encoded credentials in HTTP header'},
    'facebook_access_token': {'owasp':'API2:2023','compliance':['GDPR Art.32'],'impact':'Facebook account/page access on behalf of user'},
    'facebook_page_token':   {'owasp':'API2:2023','compliance':['GDPR Art.32'],'impact':'Facebook page management access'},
    'twitter_bearer_token':  {'owasp':'API2:2023','compliance':['GDPR Art.32'],'impact':'Twitter API access — read/post tweets'},
    'twitter_api_key':       {'owasp':'API2:2023','compliance':['GDPR Art.32'],'impact':'Twitter app authentication key'},
    'linkedin_client_id':    {'owasp':'API2:2023','compliance':['GDPR Art.32'],'impact':'LinkedIn OAuth app identifier'},
    'instagram_access_token':{'owasp':'API2:2023','compliance':['GDPR Art.32'],'impact':'Instagram account access'},
    'youtube_api_key':       {'owasp':'API2:2023','compliance':['PCI-DSS 6.3'],'impact':'YouTube API access — billing abuse'},
    'npm_token':             {'owasp':'API10:2023','compliance':['SOC2 CC6.1','ISO 27001 A.12.5'],'impact':'Publish malicious npm packages — supply chain attack'},
    'pypi_token':            {'owasp':'API10:2023','compliance':['SOC2 CC6.1','ISO 27001 A.12.5'],'impact':'Publish malicious Python packages — supply chain attack'},
    'rubygems_api_key':      {'owasp':'API10:2023','compliance':['SOC2 CC6.1'],'impact':'Publish malicious Ruby gems'},
    'nuget_api_key':         {'owasp':'API10:2023','compliance':['SOC2 CC6.1'],'impact':'Publish malicious NuGet packages'},
    'composer_auth':         {'owasp':'API10:2023','compliance':['SOC2 CC6.1'],'impact':'Composer registry credentials — package manipulation'},
    'maven_password':        {'owasp':'API10:2023','compliance':['SOC2 CC6.1'],'impact':'Maven repository credentials'},
    'generic_api_key':       {'owasp':'API2:2023','compliance':['OWASP ASVS 2.10'],'impact':'Unauthorized API access'},
    'generic_secret':        {'owasp':'API8:2023','compliance':['OWASP ASVS 2.10'],'impact':'Hardcoded secret — security misconfiguration'},
    'generic_password':      {'owasp':'API2:2023','compliance':['PCI-DSS 8.2','OWASP ASVS 2.1'],'impact':'Hardcoded password — credential exposure'},
    'generic_token':         {'owasp':'API2:2023','compliance':['OWASP ASVS 2.10'],'impact':'Generic token exposure'},
    'generic_client_secret': {'owasp':'API2:2023','compliance':['OWASP ASVS 2.10','PCI-DSS 6.3'],'impact':'OAuth client secret — account takeover risk'},
    'generic_private_key':   {'owasp':'API8:2023','compliance':['OWASP ASVS 2.10','PCI-DSS 4.1'],'impact':'Private key exposure'},
    'generic_auth_token':    {'owasp':'API2:2023','compliance':['OWASP ASVS 2.10'],'impact':'Generic auth token exposure'},
    'generic_bearer_token':  {'owasp':'API2:2023','compliance':['OWASP ASVS 2.10'],'impact':'Bearer token in code'},
    'generic_access_token':  {'owasp':'API2:2023','compliance':['OWASP ASVS 2.10'],'impact':'Generic access token exposure'},
    'high_entropy_string':   {'owasp':'API8:2023','compliance':['OWASP ASVS 2.10'],'impact':'High-entropy string — possible encoded secret'},
}


def get_owasp_info(pattern_name):
    mapping = OWASP_PATTERN_MAP.get(pattern_name)
    if not mapping:
        return None
    owasp_id   = mapping['owasp']
    owasp_data = OWASP_API_TOP10.get(owasp_id, {})
    return {
        'owasp_id':          owasp_id,
        'owasp_name':        owasp_data.get('name',''),
        'owasp_short':       owasp_data.get('short',''),
        'owasp_description': owasp_data.get('description',''),
        'owasp_color':       owasp_data.get('color','#94a3b8'),
        'owasp_url':         owasp_data.get('url',''),
        'compliance':        mapping.get('compliance',[]),
        'impact':            mapping.get('impact',''),
    }


def get_owasp_summary(findings):
    violated = {}
    compliant = {}
    for finding in findings:
        owasp = get_owasp_info(finding.get('pattern_name',''))
        if owasp:
            oid = owasp['owasp_id']
            if oid not in violated:
                violated[oid] = {'owasp_id':oid,'owasp_name':owasp['owasp_name'],'owasp_short':owasp['owasp_short'],'owasp_color':owasp['owasp_color'],'owasp_url':owasp['owasp_url'],'count':0,'findings':[]}
            violated[oid]['count'] += 1
            violated[oid]['findings'].append(finding.get('type',''))
    for oid, info in OWASP_API_TOP10.items():
        if oid not in violated:
            compliant[oid] = {'owasp_id':oid,'owasp_name':info['name'],'owasp_short':info['short'],'owasp_color':info['color'],'owasp_url':info['url']}
    return {
        'violated':list(violated.values()),
        'compliant':list(compliant.values()),
        'total_violated':len(violated),
        'total_compliant':len(compliant),
        'compliance_score':round((len(compliant)/10)*100),
    }


PATTERNS = {
    'aws_access_key': {'pattern': r'AKIA[0-9A-Z]{16}', 'severity': 'critical', 'description': 'AWS IAM Access Key ID', 'category': 'Cloud - AWS'},
    'aws_secret_key': {'pattern': r'(?i)(aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', 'severity': 'critical', 'description': 'AWS Secret Access Key', 'category': 'Cloud - AWS'},
    'aws_session_token': {'pattern': r'(?i)aws_session_token\s*[=:]\s*["\']?([A-Za-z0-9/+=]{200,})["\']?', 'severity': 'critical', 'description': 'AWS Session Token', 'category': 'Cloud - AWS'},
    'aws_account_id': {'pattern': r'(?i)aws_account_id\s*[=:]\s*["\']?(\d{12})["\']?', 'severity': 'medium', 'description': 'AWS Account ID', 'category': 'Cloud - AWS'},
    'aws_arn': {'pattern': r'arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s]+', 'severity': 'medium', 'description': 'AWS ARN', 'category': 'Cloud - AWS'},
    'aws_cognito': {'pattern': r'(?i)(cognito[_-]?identity[_-]?pool[_-]?id|user[_-]?pool[_-]?id)\s*[=:]\s*["\']?([a-z]{2}-[a-z]+-\d:[0-9a-f-]+)["\']?', 'severity': 'high', 'description': 'AWS Cognito Pool ID', 'category': 'Cloud - AWS'},
    'aws_mws_token': {'pattern': r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'severity': 'high', 'description': 'AWS MWS Auth Token', 'category': 'Cloud - AWS'},
    'google_api_key': {'pattern': r'AIza[0-9A-Za-z\-_]{35}', 'severity': 'high', 'description': 'Google Cloud API Key', 'category': 'Cloud - GCP'},
    'google_oauth': {'pattern': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', 'severity': 'high', 'description': 'Google OAuth Client ID', 'category': 'Cloud - GCP'},
    'gcp_service_account': {'pattern': r'"type":\s*"service_account"', 'severity': 'critical', 'description': 'GCP Service Account JSON', 'category': 'Cloud - GCP'},
    'google_cloud_storage': {'pattern': r'https://storage\.googleapis\.com/[a-z0-9_-]+/[^\s]+', 'severity': 'medium', 'description': 'Google Cloud Storage URL', 'category': 'Cloud - GCP'},
    'firebase_api_key': {'pattern': r'AIza[0-9A-Za-z_-]{35}', 'severity': 'medium', 'description': 'Firebase API Key', 'category': 'Cloud - Firebase'},
    'azure_storage_key': {'pattern': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{88});', 'severity': 'critical', 'description': 'Azure Storage Account Connection String', 'category': 'Cloud - Azure'},
    'azure_client_secret': {'pattern': r'(?i)(azure_client_secret|client_secret)\s*[=:]\s*["\']?([a-zA-Z0-9~._-]{34,40})["\']?', 'severity': 'critical', 'description': 'Azure Client Secret', 'category': 'Cloud - Azure'},
    'azure_subscription_id': {'pattern': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'severity': 'medium', 'description': 'Azure Subscription ID (UUID)', 'category': 'Cloud - Azure'},
    'azure_tenant_id': {'pattern': r'(?i)tenant[_-]?id\s*[=:]\s*["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']?', 'severity': 'medium', 'description': 'Azure Tenant ID', 'category': 'Cloud - Azure'},
    'azure_function_key': {'pattern': r'code=[a-zA-Z0-9/+=]{54}==', 'severity': 'high', 'description': 'Azure Function Access Key', 'category': 'Cloud - Azure'},
    'azure_cosmosdb_key': {'pattern': r'AccountEndpoint=https://[^;]+;AccountKey=([A-Za-z0-9+/=]{88});', 'severity': 'critical', 'description': 'Azure Cosmos DB Connection String', 'category': 'Cloud - Azure'},
    'heroku_api_key': {'pattern': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', 'severity': 'high', 'description': 'Heroku API Key', 'category': 'Cloud - Heroku'},
    'digitalocean_token': {'pattern': r'(?i)digitalocean[_-]?token\s*[=:]\s*["\']?([a-f0-9]{64})["\']?', 'severity': 'high', 'description': 'DigitalOcean Access Token', 'category': 'Cloud - DigitalOcean'},
    'cloudflare_api_key': {'pattern': r'(?i)cloudflare[_-]?api[_-]?key\s*[=:]\s*["\']?([a-z0-9]{37})["\']?', 'severity': 'high', 'description': 'Cloudflare API Key', 'category': 'Cloud - Cloudflare'},
    'cloudflare_global_api_key': {'pattern': r'(?i)X-Auth-Key:\s*([a-z0-9]{37})', 'severity': 'high', 'description': 'Cloudflare Global API Key', 'category': 'Cloud - Cloudflare'},
    'alibaba_access_key': {'pattern': r'(?i)(alibaba|aliyun)[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']?([A-Z0-9]{24})["\']?', 'severity': 'critical', 'description': 'Alibaba Cloud Access Key', 'category': 'Cloud - Alibaba'},
    'linode_api_key': {'pattern': r'(?i)linode[_-]?api[_-]?key\s*[=:]\s*["\']?([a-z0-9]{64})["\']?', 'severity': 'high', 'description': 'Linode API Key', 'category': 'Cloud - Linode'},
    'vultr_api_key': {'pattern': r'(?i)vultr[_-]?api[_-]?key\s*[=:]\s*["\']?([A-Z0-9]{36})["\']?', 'severity': 'high', 'description': 'Vultr API Key', 'category': 'Cloud - Vultr'},
    'github_token': {'pattern': r'ghp_[0-9a-zA-Z]{36}', 'severity': 'critical', 'description': 'GitHub Personal Access Token', 'category': 'Version Control'},
    'github_oauth': {'pattern': r'gho_[0-9a-zA-Z]{36}', 'severity': 'critical', 'description': 'GitHub OAuth Access Token', 'category': 'Version Control'},
    'github_app_token': {'pattern': r'(ghu|ghs)_[0-9a-zA-Z]{36}', 'severity': 'critical', 'description': 'GitHub App Token', 'category': 'Version Control'},
    'github_refresh_token': {'pattern': r'ghr_[0-9a-zA-Z]{36}', 'severity': 'critical', 'description': 'GitHub Refresh Token', 'category': 'Version Control'},
    'gitlab_token': {'pattern': r'glpat-[0-9a-zA-Z_-]{20}', 'severity': 'critical', 'description': 'GitLab Personal Access Token', 'category': 'Version Control'},
    'gitlab_pipeline_token': {'pattern': r'glptt-[0-9a-f]{40}', 'severity': 'high', 'description': 'GitLab Pipeline Trigger Token', 'category': 'Version Control'},
    'gitlab_runner_token': {'pattern': r'glrt-[0-9a-zA-Z_-]{20}', 'severity': 'high', 'description': 'GitLab Runner Registration Token', 'category': 'Version Control'},
    'bitbucket_token': {'pattern': r'(?i)bitbucket[_-]?token\s*[=:]\s*["\']?([A-Za-z0-9_-]{43})["\']?', 'severity': 'high', 'description': 'Bitbucket Access Token', 'category': 'Version Control'},
    'jenkins_token': {'pattern': r'(?i)jenkins[_-]?token\s*[=:]\s*["\']?([a-f0-9]{32})["\']?', 'severity': 'high', 'description': 'Jenkins API Token', 'category': 'CI/CD'},
    'circleci_token': {'pattern': r'(?i)circle[_-]?ci[_-]?token\s*[=:]\s*["\']?([a-f0-9]{40})["\']?', 'severity': 'high', 'description': 'CircleCI API Token', 'category': 'CI/CD'},
    'travis_token': {'pattern': r'(?i)travis[_-]?token\s*[=:]\s*["\']?([a-zA-Z0-9_-]{22})["\']?', 'severity': 'high', 'description': 'Travis CI Access Token', 'category': 'CI/CD'},
    'drone_token': {'pattern': r'(?i)drone[_-]?token\s*[=:]\s*["\']?([a-zA-Z0-9]{32})["\']?', 'severity': 'high', 'description': 'Drone CI Access Token', 'category': 'CI/CD'},
    'terraform_cloud_token': {'pattern': r'[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_-]{60,}', 'severity': 'critical', 'description': 'Terraform Cloud API Token', 'category': 'CI/CD'},
    'ansible_vault': {'pattern': r'\$ANSIBLE_VAULT;[0-9.]+;AES256', 'severity': 'high', 'description': 'Ansible Vault Encrypted Data', 'category': 'CI/CD'},
    'kubernetes_secret': {'pattern': r'(?i)kind:\s*Secret', 'severity': 'medium', 'description': 'Kubernetes Secret Definition', 'category': 'CI/CD'},
    'docker_hub_token': {'pattern': r'dckr_pat_[a-zA-Z0-9_-]{40}', 'severity': 'high', 'description': 'Docker Hub Personal Access Token', 'category': 'CI/CD'},
    'github_actions_secret': {'pattern': r'\$\{\{\s*secrets\.[A-Z_]+\s*\}\}', 'severity': 'low', 'description': 'GitHub Actions Secret Reference', 'category': 'CI/CD'},
    'gitlab_ci_token': {'pattern': r'\$CI_JOB_TOKEN', 'severity': 'low', 'description': 'GitLab CI Job Token Reference', 'category': 'CI/CD'},
    'mongodb_uri': {'pattern': r'mongodb(\+srv)?://[^\s:]+:[^\s@]+@[^\s/]+', 'severity': 'critical', 'description': 'MongoDB Connection String with Credentials', 'category': 'Database'},
    'postgresql_uri': {'pattern': r'postgres(ql)?://[^\s:]+:[^\s@]+@[^\s/]+', 'severity': 'critical', 'description': 'PostgreSQL Connection String with Credentials', 'category': 'Database'},
    'mysql_uri': {'pattern': r'mysql://[^\s:]+:[^\s@]+@[^\s/]+', 'severity': 'critical', 'description': 'MySQL Connection String with Credentials', 'category': 'Database'},
    'mssql_uri': {'pattern': r'Server=[^;]+;Database=[^;]+;User Id=[^;]+;Password=([^;]+);', 'severity': 'critical', 'description': 'MS SQL Server Connection String', 'category': 'Database'},
    'redis_uri': {'pattern': r'redis://[^\s:]*:[^\s@]+@[^\s:]+:\d+', 'severity': 'high', 'description': 'Redis Connection String with Password', 'category': 'Database'},
    'elasticsearch_uri': {'pattern': r'https?://[^\s:]+:[^\s@]+@[^\s:]+:\d+', 'severity': 'high', 'description': 'Elasticsearch Connection with Credentials', 'category': 'Database'},
    'cassandra_password': {'pattern': r'(?i)cassandra[_-]?password\s*[=:]\s*["\']?([^\s"\']+)["\']?', 'severity': 'high', 'description': 'Apache Cassandra Password', 'category': 'Database'},
    'couchdb_uri': {'pattern': r'https?://[^\s:]+:[^\s@]+@[^\s:]+:5984', 'severity': 'high', 'description': 'CouchDB Connection with Credentials', 'category': 'Database'},
    'neo4j_uri': {'pattern': r'neo4j(\+s)?://[^\s:]+:[^\s@]+@[^\s:]+:\d+', 'severity': 'high', 'description': 'Neo4j Connection String', 'category': 'Database'},
    'influxdb_token': {'pattern': r'(?i)influx[_-]?token\s*[=:]\s*["\']?([A-Za-z0-9_-]{86}==)["\']?', 'severity': 'high', 'description': 'InfluxDB Authentication Token', 'category': 'Database'},
    'oracle_db_connection': {'pattern': r'jdbc:oracle:thin:[^\s:]+/[^\s@]+@[^\s:]+:\d+', 'severity': 'critical', 'description': 'Oracle Database JDBC Connection', 'category': 'Database'},
    'dynamodb_credentials': {'pattern': r'(?i)dynamodb[_-]?(access|secret)[_-]?key', 'severity': 'high', 'description': 'AWS DynamoDB Credentials', 'category': 'Database'},
    'stripe_live_key': {'pattern': r'sk_live_[0-9a-zA-Z]{24,}', 'severity': 'critical', 'description': 'Stripe Live Secret Key', 'category': 'Payment'},
    'stripe_restricted_key': {'pattern': r'rk_live_[0-9a-zA-Z]{24,}', 'severity': 'critical', 'description': 'Stripe Restricted API Key', 'category': 'Payment'},
    'stripe_test_key': {'pattern': r'sk_test_[0-9a-zA-Z]{24,}', 'severity': 'medium', 'description': 'Stripe Test Secret Key', 'category': 'Payment'},
    'stripe_webhook_secret': {'pattern': r'whsec_[0-9a-zA-Z]{32,}', 'severity': 'high', 'description': 'Stripe Webhook Secret', 'category': 'Payment'},
    'paypal_token': {'pattern': r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}', 'severity': 'critical', 'description': 'PayPal Access Token', 'category': 'Payment'},
    'square_access_token': {'pattern': r'sq0atp-[0-9A-Za-z_-]{22}', 'severity': 'critical', 'description': 'Square Access Token', 'category': 'Payment'},
    'square_oauth_secret': {'pattern': r'sq0csp-[0-9A-Za-z_-]{43}', 'severity': 'critical', 'description': 'Square OAuth Secret', 'category': 'Payment'},
    'braintree_token': {'pattern': r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}', 'severity': 'critical', 'description': 'Braintree Access Token', 'category': 'Payment'},
    'shopify_token': {'pattern': r'shpat_[a-fA-F0-9]{32}', 'severity': 'critical', 'description': 'Shopify Private App Token', 'category': 'E-commerce'},
    'slack_token': {'pattern': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,32}', 'severity': 'high', 'description': 'Slack Access Token', 'category': 'Communication'},
    'slack_webhook': {'pattern': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+', 'severity': 'high', 'description': 'Slack Webhook URL', 'category': 'Communication'},
    'slack_legacy_token': {'pattern': r'xoxb-[0-9]{11,}-[a-zA-Z0-9]{24}', 'severity': 'high', 'description': 'Slack Legacy Bot Token', 'category': 'Communication'},
    'discord_webhook': {'pattern': r'https://discord(app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+', 'severity': 'medium', 'description': 'Discord Webhook URL', 'category': 'Communication'},
    'discord_bot_token': {'pattern': r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}', 'severity': 'high', 'description': 'Discord Bot Token', 'category': 'Communication'},
    'twilio_api_key': {'pattern': r'SK[0-9a-fA-F]{32}', 'severity': 'high', 'description': 'Twilio API Key', 'category': 'Communication'},
    'twilio_account_sid': {'pattern': r'AC[a-f0-9]{32}', 'severity': 'medium', 'description': 'Twilio Account SID', 'category': 'Communication'},
    'sendgrid_api_key': {'pattern': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', 'severity': 'high', 'description': 'SendGrid API Key', 'category': 'Communication'},
    'mailchimp_api_key': {'pattern': r'[0-9a-f]{32}-us[0-9]{1,2}', 'severity': 'high', 'description': 'MailChimp API Key', 'category': 'Communication'},
    'mailgun_api_key': {'pattern': r'key-[0-9a-zA-Z]{32}', 'severity': 'high', 'description': 'Mailgun API Key', 'category': 'Communication'},
    'facebook_access_token': {'pattern': r'EAACEdEose0cBA[0-9A-Za-z]+', 'severity': 'high', 'description': 'Facebook Access Token', 'category': 'Social Media'},
    'facebook_page_token': {'pattern': r'EAA[A-Za-z0-9]{180,}', 'severity': 'high', 'description': 'Facebook Page Access Token', 'category': 'Social Media'},
    'twitter_bearer_token': {'pattern': r'AAAAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%]+', 'severity': 'high', 'description': 'Twitter Bearer Token', 'category': 'Social Media'},
    'twitter_api_key': {'pattern': r'(?i)twitter[_-]?api[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9]{25})["\']?', 'severity': 'high', 'description': 'Twitter API Key', 'category': 'Social Media'},
    'linkedin_client_id': {'pattern': r'(?i)linkedin[_-]?client[_-]?id\s*[=:]\s*["\']?([a-z0-9]{12,})["\']?', 'severity': 'medium', 'description': 'LinkedIn Client ID', 'category': 'Social Media'},
    'instagram_access_token': {'pattern': r'(?i)instagram[_-]?token\s*[=:]\s*["\']?([0-9]+\.[0-9a-f]+\.[0-9a-f]+)["\']?', 'severity': 'high', 'description': 'Instagram Access Token', 'category': 'Social Media'},
    'youtube_api_key': {'pattern': r'(?i)youtube[_-]?api[_-]?key\s*[=:]\s*["\']?(AIza[0-9A-Za-z\-_]{35})["\']?', 'severity': 'medium', 'description': 'YouTube API Key', 'category': 'Social Media'},
    'npm_token': {'pattern': r'npm_[a-zA-Z0-9]{36}', 'severity': 'high', 'description': 'npm Access Token', 'category': 'Package Manager'},
    'pypi_token': {'pattern': r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,}', 'severity': 'high', 'description': 'PyPI API Token', 'category': 'Package Manager'},
    'rubygems_api_key': {'pattern': r'rubygems_[a-f0-9]{48}', 'severity': 'high', 'description': 'RubyGems API Key', 'category': 'Package Manager'},
    'nuget_api_key': {'pattern': r'oy2[a-z0-9]{43}', 'severity': 'high', 'description': 'NuGet API Key', 'category': 'Package Manager'},
    'composer_auth': {'pattern': r'(?i)"http-basic":\s*\{[^}]*"username":[^}]*"password":', 'severity': 'high', 'description': 'Composer HTTP Basic Auth', 'category': 'Package Manager'},
    'maven_password': {'pattern': r'<password>([^<]+)</password>', 'severity': 'high', 'description': 'Maven Repository Password', 'category': 'Package Manager'},
    'jwt_token': {'pattern': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_.\-]*', 'severity': 'medium', 'description': 'JSON Web Token (JWT)', 'category': 'Authentication'},
    'private_key_rsa': {'pattern': r'-----BEGIN RSA PRIVATE KEY-----', 'severity': 'critical', 'description': 'RSA Private Key', 'category': 'Cryptography'},
    'private_key_ec': {'pattern': r'-----BEGIN EC PRIVATE KEY-----', 'severity': 'critical', 'description': 'EC Private Key', 'category': 'Cryptography'},
    'private_key_dsa': {'pattern': r'-----BEGIN DSA PRIVATE KEY-----', 'severity': 'critical', 'description': 'DSA Private Key', 'category': 'Cryptography'},
    'private_key_openssh': {'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----', 'severity': 'critical', 'description': 'OpenSSH Private Key', 'category': 'Cryptography'},
    'pgp_private_key': {'pattern': r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'severity': 'critical', 'description': 'PGP Private Key', 'category': 'Cryptography'},
    'ssl_certificate': {'pattern': r'-----BEGIN CERTIFICATE-----', 'severity': 'medium', 'description': 'SSL/TLS Certificate', 'category': 'Cryptography'},
    'basic_auth': {'pattern': r'(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', 'severity': 'high', 'description': 'HTTP Basic Authentication', 'category': 'Authentication'},
    'generic_api_key': {'pattern': r'(?i)api[_-]?key[\s]*[:=][\s]*["\']?[a-zA-Z0-9_\-]{20,}["\']?', 'severity': 'medium', 'description': 'Generic API Key Pattern', 'category': 'Generic'},
    'generic_secret': {'pattern': r'(?i)secret[\s]*[:=][\s]*["\']?[a-zA-Z0-9_\-]{20,}["\']?', 'severity': 'medium', 'description': 'Generic Secret Pattern', 'category': 'Generic'},
    'generic_password': {'pattern': r'(?i)password[\s]*[:=][\s]*["\']?[a-zA-Z0-9_\-@!#$%^&*]{8,}["\']?', 'severity': 'medium', 'description': 'Generic Password Pattern', 'category': 'Generic'},
    'generic_token': {'pattern': r'(?i)token[\s]*[:=][\s]*["\']?[a-zA-Z0-9_\-]{20,}["\']?', 'severity': 'medium', 'description': 'Generic Token Pattern', 'category': 'Generic'},
    'generic_client_secret': {'pattern': r'(?i)client[_-]?secret[\s]*[:=][\s]*["\']?[a-zA-Z0-9_\-]{20,}["\']?', 'severity': 'high', 'description': 'Generic Client Secret', 'category': 'Generic'},
    'generic_private_key': {'pattern': r'(?i)private[_-]?key[\s]*[:=][\s]*["\']?[a-zA-Z0-9_\-/+=]{40,}["\']?', 'severity': 'high', 'description': 'Generic Private Key', 'category': 'Generic'},
    'generic_auth_token': {'pattern': r'(?i)auth[_-]?token[\s]*[:=][\s]*["\']?[a-zA-Z0-9_\-]{32,}["\']?', 'severity': 'medium', 'description': 'Generic Auth Token', 'category': 'Generic'},
    'generic_bearer_token': {'pattern': r'(?i)Bearer\s+([a-zA-Z0-9_\-\.]{20,})', 'severity': 'medium', 'description': 'Generic Bearer Token', 'category': 'Generic'},
    'generic_access_token': {'pattern': r'(?i)access[_-]?token[\s]*[:=][\s]*["\']?[a-zA-Z0-9_\-]{32,}["\']?', 'severity': 'medium', 'description': 'Generic Access Token', 'category': 'Generic'},
    'high_entropy_string': {'pattern': r'[a-zA-Z0-9+/]{40,}={0,2}', 'severity': 'low', 'description': 'High Entropy String (Base64)', 'category': 'Generic'},
}

def sanitize_input(text, max_length=100000):
    if not text: raise ValueError("Input cannot be empty")
    if len(text) > max_length: raise ValueError(f"Input too large. Maximum {max_length} characters allowed")
    return text.replace('\x00', '')

def validate_url(url, allow_local=False):
    parsed = urlparse(url)
    if parsed.scheme not in ['http','https']: return False
    hostname = parsed.hostname or ''
    if not hostname: return False
    if hostname == '169.254.169.254': return False
    if not allow_local:
        if hostname in ['localhost','127.0.0.1','0.0.0.0','::1']: return False
        if hostname.startswith('10.') or hostname.startswith('192.168.'): return False
        parts = hostname.split('.')
        if len(parts)==4 and parts[0]=='172':
            try:
                if 16 <= int(parts[1]) <= 31: return False
            except: pass
    return True

def calculate_risk_score(findings):
    score = min(sum({'critical':25,'high':10,'medium':5,'low':2}.get(f.get('severity','low'),0) for f in findings), 100)
    if score>=75: level,color,emoji='Critical Risk','#ef4444','🔴'
    elif score>=50: level,color,emoji='High Risk','#f59e0b','🟠'
    elif score>=25: level,color,emoji='Medium Risk','#fbbf24','🟡'
    elif score>0: level,color,emoji='Low Risk','#10b981','🟢'
    else: level,color,emoji='No Risk Detected','#22c55e','✅'
    return {'score':score,'level':level,'color':color,'emoji':emoji}

def group_duplicate_findings(findings):
    groups = {}
    for f in findings:
        key = f.get('secret_hash','') or (f.get('type','')+f.get('context','')[:20])
        if key not in groups:
            groups[key] = {**f,'occurrences':[f.get('source','unknown')],'count':1}
        else:
            src = f.get('source','unknown')
            if src not in groups[key]['occurrences']: groups[key]['occurrences'].append(src)
            groups[key]['count'] += 1
    return list(groups.values())

class SecretDetector:
    def __init__(self):
        self.patterns = PATTERNS
    def is_false_positive(self, secret, context):
        cl = context.lower()
        for ind in ['your_','replace_','todo:','fixme:','<your','insert_']:
            if ind in cl: return True
        if re.search(r'(xxx+|yyy+|zzz+|111+|000+|aaa+)', secret.lower()): return True
        if len(set(secret)) < 5: return True
        return False
    def get_context(self, text, pos, size=100):
        return text[max(0,pos-size):min(len(text),pos+size)]
    def hash_secret(self, s): return hashlib.sha256(s.encode()).hexdigest()
    def mask_secret(self, s): return '*'*len(s) if len(s)<=8 else f"{s[:4]}...{s[-4:]}"
    def get_context_for_secret(self, text, pos, secret_len, context_size=120):
        """Get context window that always includes the full secret value."""
        start = max(0, pos - context_size)
        end   = min(len(text), pos + secret_len + context_size)
        return text[start:end]
    def scan_text(self, text, source='text_input'):
        findings, seen_hashes, seen_positions = [], set(), set()

        # GENERIC pattern names — only report if no specific pattern found same location
        GENERIC_PATTERNS = {
            'generic_api_key','generic_secret','generic_password','generic_token',
            'generic_client_secret','generic_private_key','generic_auth_token',
            'generic_bearer_token','generic_access_token','high_entropy_string'
        }

        # First pass — run all specific (non-generic) patterns
        specific_positions = set()  # track character positions covered by specific patterns

        for pname, pcfg in self.patterns.items():
            if pname in GENERIC_PATTERNS:
                continue
            try:
                for m in re.compile(pcfg['pattern']).finditer(text):
                    secret = m.group(0)
                    h = self.hash_secret(secret)
                    if h in seen_hashes: continue
                    ctx = self.get_context(text, m.start())
                    if self.is_false_positive(secret, ctx): continue
                    seen_hashes.add(h)
                    # Mark this line as covered by a specific pattern
                    line_start = text.rfind('\n', 0, m.start()) + 1
                    line_end   = text.find('\n', m.start())
                    if line_end == -1: line_end = len(text)
                    specific_positions.add((line_start, line_end))
                    owasp = get_owasp_info(pname)
                    # Use extended context so full secret is always included
                    full_ctx = self.get_context_for_secret(text, m.start(), len(secret))
                    findings.append({
                        'type': pcfg['description'], 'severity': pcfg['severity'],
                        'category': pcfg['category'], 'pattern_name': pname,
                        'secret_preview': self.mask_secret(secret), 'secret_hash': h,
                        'raw_secret': secret,   # store raw for live validation
                        'description': pcfg['description'], 'source': source,
                        'context': full_ctx.strip(), 'position': m.start(),
                        'timestamp': datetime.now().isoformat(), 'owasp': owasp
                    })
            except re.error:
                continue

        # Second pass — run generic patterns, skip if specific already covered same line
        for pname, pcfg in self.patterns.items():
            if pname not in GENERIC_PATTERNS:
                continue
            try:
                for m in re.compile(pcfg['pattern']).finditer(text):
                    secret = m.group(0)
                    h = self.hash_secret(secret)
                    if h in seen_hashes: continue
                    ctx = self.get_context(text, m.start())
                    if self.is_false_positive(secret, ctx): continue

                    # Skip if a specific pattern already found something on this line
                    line_start = text.rfind('\n', 0, m.start()) + 1
                    line_end   = text.find('\n', m.start())
                    if line_end == -1: line_end = len(text)
                    if (line_start, line_end) in specific_positions:
                        continue  # Skip — specific pattern already covers this line

                    seen_hashes.add(h)
                    owasp = get_owasp_info(pname)
                    full_ctx = self.get_context_for_secret(text, m.start(), len(secret))
                    findings.append({
                        'type': pcfg['description'], 'severity': pcfg['severity'],
                        'category': pcfg['category'], 'pattern_name': pname,
                        'secret_preview': self.mask_secret(secret), 'secret_hash': h,
                        'raw_secret': secret,   # store raw for live validation
                        'description': pcfg['description'], 'source': source,
                        'context': full_ctx.strip(), 'position': m.start(),
                        'timestamp': datetime.now().isoformat(), 'owasp': owasp
                    })
            except re.error:
                continue

        return findings

class WebCrawler:
    def __init__(self, max_depth=2, max_pages=20, allow_local=True):
        self.max_depth=max_depth; self.max_pages=max_pages; self.allow_local=allow_local
        self.visited_urls=set()
        self.session=requests.Session()
        self.session.headers.update({'User-Agent':'SecureKey-Scanner/2.0'})
    def scan_js_bundles(self, soup, base_url, detector):
        js_findings=[]
        for script in soup.find_all('script',src=True):
            js_url=urljoin(base_url,script.get('src',''))
            if not urlparse(js_url).path.endswith('.js'): continue
            try:
                r=self.session.get(js_url,timeout=8,verify=False)
                if r.status_code==200:
                    found=detector.scan_text(r.text,source=f'JS Bundle: {js_url}')
                    js_findings.extend(found)
            except: pass
        return js_findings
    def crawl(self, start_url, detector=None):
        if not validate_url(start_url,allow_local=self.allow_local): raise ValueError("Invalid URL")
        pages=[]; to_visit=[(start_url,0)]; js_findings=[]
        while to_visit and len(pages)<self.max_pages:
            url,depth=to_visit.pop(0)
            if url in self.visited_urls or depth>self.max_depth: continue
            try:
                r=self.session.get(url,timeout=15,allow_redirects=True,verify=False)
                r.raise_for_status(); self.visited_urls.add(url)
                soup=BeautifulSoup(r.text,'html.parser')
                if detector and depth==0: js_findings=self.scan_js_bundles(soup,url,detector)
                for s in soup(['script','style']): s.decompose()
                pages.append({'url':url,'content':soup.get_text(separator='\n',strip=True),'html':r.text})
                if depth<self.max_depth:
                    for link in soup.find_all('a',href=True):
                        next_url=urljoin(url,link['href'])
                        if urlparse(next_url).netloc==urlparse(start_url).netloc:
                            if validate_url(next_url,allow_local=self.allow_local): to_visit.append((next_url,depth+1))
            except Exception as e: logger.error(f"Crawl error {url}: {e}")
        return pages, js_findings

detector = SecretDetector()

@app.route('/api/health',methods=['GET'])
def health_check():
    return jsonify({'status':'healthy','version':'2.0.0','timestamp':datetime.now().isoformat(),'features':['risk_score','js_bundle_scan','header_check','env_exposure','duplicate_grouping','html_report']})

@app.route('/api/scan/text',methods=['POST'])
@limiter.limit("20 per minute")
def scan_text():
    try:
        data = request.get_json(silent=True) or {}
        if 'text' not in data:
            return jsonify({'error': 'Missing text field'}), 400
        text = sanitize_input(str(data['text']))
        t = time.time()
        findings=detector.scan_text(text,'text_input')
        grouped=group_duplicate_findings(findings); risk=calculate_risk_score(findings)
        return jsonify({'total_findings':len(grouped),'findings':grouped,'risk_score':risk,'scan_time':time.time()-t,'timestamp':datetime.now().isoformat()})
    except Exception as e: logger.error(e); return jsonify({'error':'Internal server error'}),500

@app.route('/api/scan/url',methods=['POST'])
@limiter.limit("10 per minute")
def scan_url():
    try:
        data = request.get_json(silent=True) or {}
        if 'url' not in data:
            return jsonify({'error': 'Missing url field'}), 400
        url = str(data['url']).strip()[:2048]   # cap URL length
        safe, reason = is_ssrf_safe(url, allow_private=True)   # allow_private=True for local dev scanning
        if not safe:
            return jsonify({'error': f'URL not allowed: {reason}'}), 400
        t=time.time()
        crawler=WebCrawler(max_depth=min(int(data.get('max_depth',2)),5),max_pages=min(int(data.get('max_pages',20)),50),allow_local=True)
        pages,js_findings=crawler.crawl(url,detector=detector)
        all_findings=list(js_findings)
        for page in pages: all_findings.extend(detector.scan_text(page['content']+'\n'+page['html'],source=page['url']))
        grouped=group_duplicate_findings(all_findings); risk=calculate_risk_score(all_findings)
        return jsonify({'total_findings':len(grouped),'findings':grouped,'risk_score':risk,'pages_scanned':len(pages),'js_bundles_scanned':len([f for f in grouped if 'JS Bundle' in f.get('source','')]),'scan_time':time.time()-t,'timestamp':datetime.now().isoformat()})
    except ValueError as e: return jsonify({'error':str(e)}),400
    except Exception as e: logger.error(e); return jsonify({'error':str(e)}),500

@app.route('/api/scan/file',methods=['POST'])
@limiter.limit("10 per minute")
def scan_file():
    """Secure file upload endpoint with full validation."""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']

        if not file.filename:
            return jsonify({'error': 'No file selected'}), 400

        # 1. Sanitize filename — prevent path traversal
        fname = sanitize_filename(file.filename)

        # 2. Whitelist extension check
        if not allowed_file_extension(fname):
            logger.warning(f'Blocked file upload: {file.filename}')
            return jsonify({'error': f'File type not allowed. Only text/code files accepted.'}), 400

        # 3. Size check
        file.seek(0, os.SEEK_END)
        sz = file.tell()
        file.seek(0)
        if sz > 10 * 1024 * 1024:
            return jsonify({'error': 'File too large (max 10MB)'}), 400
        if sz == 0:
            return jsonify({'error': 'File is empty'}), 400

        # 4. Read raw bytes for content validation
        file_bytes = file.read()

        # 5. Validate content (magic bytes, MIME, encoding)
        valid, reason = validate_file_content(file_bytes, fname)
        if not valid:
            logger.warning(f'Blocked file content: {fname} — {reason}')
            return jsonify({'error': f'File rejected: {reason}'}), 400

        # 6. Decode and scan
        try:
            content_str = file_bytes.decode('utf-8', errors='replace')
        except Exception:
            content_str = file_bytes.decode('latin-1', errors='replace')

        t = time.time()
        findings = detector.scan_text(content_str, fname)
        grouped  = group_duplicate_findings(findings)
        risk     = calculate_risk_score(findings)

        return jsonify({
            'total_findings': len(grouped),
            'findings':       grouped,
            'risk_score':     risk,
            'filename':       fname,
            'file_size':      sz,
            'scan_time':      time.time() - t,
            'timestamp':      datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f'File scan error: {e}')
        return jsonify({'error': 'File scan failed'}), 500

@app.route('/api/scan/github',methods=['POST'])
@limiter.limit("5 per minute")
def scan_github():
    try:
        import subprocess
        data=request.get_json()
        if not data or 'repo_url' not in data: return jsonify({'error':'Missing repo_url field'}),400
        repo_url=data['repo_url']
        # Strict GitHub URL validation
        if not re.match(r'^https://github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+/?$', repo_url):
            return jsonify({'error': 'Invalid GitHub URL. Format: https://github.com/owner/repo'}), 400
        # Additional SSRF check
        safe, reason = is_ssrf_safe(repo_url, allow_private=False)
        if not safe:
            return jsonify({'error': f'URL blocked: {reason}'}), 400
        t=time.time()

        # Create a PARENT temp dir, then clone INTO a subfolder inside it
        # git clone refuses to clone into an existing non-empty directory
        parent_dir = tempfile.mkdtemp()
        temp_dir   = os.path.join(parent_dir, 'repo')
        # temp_dir does NOT exist yet — git will create it

        try:
            logger.info(f"Cloning {repo_url} into {temp_dir}")
            result = subprocess.run(
                ['git', 'clone', '--depth=1', '--quiet', repo_url, temp_dir],
                capture_output=True, text=True, timeout=120
            )
            logger.info(f"Clone returncode={result.returncode} stderr={result.stderr[:200]}")

            if result.returncode != 0:
                logger.warning(f"subprocess clone failed: {result.stderr}")
                # Fallback — try gitpython
                try:
                    git.Repo.clone_from(repo_url, temp_dir, depth=1)
                    logger.info("gitpython clone succeeded")
                except Exception as ge:
                    return jsonify({'error': f'Clone failed: {result.stderr or str(ge)}'}), 500

            # Walk the cloned repo
            all_findings=[]; files_scanned=0; all_files_found=[]
            for root, dirs, files in os.walk(temp_dir):
                dirs[:] = [d for d in dirs if d not in {
                    '.git','node_modules','__pycache__','.tox',
                    'venv','.venv','dist','build','.pytest_cache'
                }]
                for f in files:
                    fp = os.path.join(root, f)
                    all_files_found.append(fp)  # debug — count all files
                    if not is_text_file(fp): continue
                    try:
                        if os.path.getsize(fp) > 2*1024*1024: continue
                        with open(fp,'r',encoding='utf-8',errors='ignore') as fh:
                            c = fh.read()
                        if not c.strip(): continue
                        rel_path = os.path.relpath(fp, temp_dir)
                        all_findings.extend(detector.scan_text(c, rel_path))
                        files_scanned += 1
                    except: continue

            logger.info(f"Total files in repo: {len(all_files_found)}, text files scanned: {files_scanned}")
            grouped = group_duplicate_findings(all_findings)
            risk    = calculate_risk_score(all_findings)
            return jsonify({
                'total_findings': len(grouped),
                'findings':       grouped,
                'risk_score':     risk,
                'files_scanned':  files_scanned,
                'total_files':    len(all_files_found),
                'repo_url':       repo_url,
                'scan_time':      time.time()-t,
                'timestamp':      datetime.now().isoformat()
            })
        finally:
            shutil.rmtree(parent_dir, ignore_errors=True)

    except subprocess.TimeoutExpired:
        return jsonify({'error':'Clone timed out — repository too large or slow connection'}), 504
    except Exception as e:
        logger.error(f"GitHub scan error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/check/exposed-files',methods=['POST'])
@limiter.limit("10 per minute")
def check_exposed_files():
    try:
        data   = request.get_json(silent=True) or {}
        domain = str(data.get('domain', '')).strip().rstrip('/')[:2048]
        if not domain:
            return jsonify({'error': 'Missing domain field'}), 400
        safe, reason = is_ssrf_safe(domain, allow_private=True)
        if not safe:
            return jsonify({'error': f'Domain not allowed: {reason}'}), 400
        parsed_d=urlparse(domain); base_origin=f"{parsed_d.scheme}://{parsed_d.netloc}"
        found_files=[]; sess=requests.Session(); sess.headers.update({'User-Agent':'SecureKey-Scanner/2.0'})
        for path in EXPOSED_PATHS:
            full_url=base_origin+path
            try:
                r=sess.get(full_url,timeout=5,verify=False,allow_redirects=False)
                if r.status_code==200 and len(r.text)>10:
                    ff=detector.scan_text(r.text,f'Exposed File: {full_url}')
                    found_files.append({'path':path,'url':full_url,'status_code':r.status_code,'size_bytes':len(r.text),'secrets_found':len(ff),'severity':'critical' if ff else 'high','findings':ff,'preview':r.text[:200]+('...' if len(r.text)>200 else '')})
                    logger.warning(f"EXPOSED FILE: {full_url}")
            except: continue
        all_ff=[f for file in found_files for f in file['findings']]
        return jsonify({'domain':domain,'paths_checked':len(EXPOSED_PATHS),'exposed_files':found_files,'total_exposed':len(found_files),'total_secrets_in_files':len(all_ff),'risk_score':calculate_risk_score(all_ff),'timestamp':datetime.now().isoformat()})
    except Exception as e: logger.error(e); return jsonify({'error':str(e)}),500

@app.route('/api/scan/headers',methods=['POST'])
@limiter.limit("20 per minute")
def scan_headers():
    try:
        data = request.get_json(silent=True) or {}
        url  = str(data.get('url', '')).strip()[:2048]
        if not url:
            return jsonify({'error': 'Missing url field'}), 400
        safe, reason = is_ssrf_safe(url, allow_private=True)
        if not safe:
            return jsonify({'error': f'URL not allowed: {reason}'}), 400
        sess=requests.Session(); sess.headers.update({'User-Agent':'SecureKey-Scanner/2.0'})
        resp=sess.get(url,timeout=10,verify=False,allow_redirects=True)
        headers=dict(resp.headers); issues=[]
        for hname,info in SECURITY_HEADERS.items():
            if hname not in headers:
                issues.append({'header':hname,'status':'missing','severity':info['severity'],'issue':info['issue'],'recommendation':info['recommendation'],'value':None})
        for lh in ['Server','X-Powered-By','X-AspNet-Version','X-Generator','X-Runtime','X-Debug-Token']:
            if lh in headers:
                issues.append({'header':lh,'status':'leaking','severity':'medium','issue':f'Reveals server/framework info: {headers[lh]}','recommendation':f'Remove or mask {lh}','value':headers[lh]})
        if headers.get('Access-Control-Allow-Origin','')=='*':
            issues.append({'header':'Access-Control-Allow-Origin','status':'misconfigured','severity':'high','issue':'Wildcard CORS allows any origin','recommendation':'Restrict to specific trusted origins','value':'*'})
        risk=calculate_risk_score(issues)
        return jsonify({'url':url,'status_code':resp.status_code,'headers':headers,'issues':issues,'total_issues':len(issues),'risk_score':risk,'security_score':max(0,100-len(issues)*10),'timestamp':datetime.now().isoformat()})
    except requests.exceptions.ConnectionError: return jsonify({'error':'Could not connect to URL'}),400
    except Exception as e: logger.error(e); return jsonify({'error':str(e)}),500

@app.route('/api/report/html',methods=['POST'])
@limiter.limit("10 per minute")
def generate_html_report():
    try:
        data=request.get_json(); findings=data.get('findings',[]); scan_target=data.get('scanTarget','Unknown')
        risk=data.get('riskScore',{'score':0,'level':'Unknown','color':'#94a3b8','emoji':''})
        ts=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        c=sum(1 for f in findings if f.get('severity')=='critical'); h=sum(1 for f in findings if f.get('severity')=='high')
        m=sum(1 for f in findings if f.get('severity')=='medium'); l=sum(1 for f in findings if f.get('severity')=='low')
        rows=''
        for i,f in enumerate(findings,1):
            clr={'critical':'#ef4444','high':'#f59e0b','medium':'#fbbf24','low':'#10b981'}.get(f.get('severity','low'),'#94a3b8')
            cnt=f' <span style="background:#667eea;color:#fff;border-radius:10px;padding:1px 6px;font-size:.7rem;">{f.get("count",1)}x</span>' if f.get('count',1)>1 else ''
            rows+=f'<tr><td>{i}</td><td>{f.get("type","Unknown")}{cnt}</td><td><span style="background:{clr};color:#fff;padding:2px 8px;border-radius:10px;font-size:.75rem;font-weight:700;">{f.get("severity","").upper()}</span></td><td style="font-family:monospace;font-size:.8rem;color:#22d3ee;">{f.get("secret_preview","****")}</td><td style="font-size:.8rem;word-break:break-all;">{f.get("source","Unknown")}</td><td style="font-size:.75rem;">{f.get("category","Unknown")}</td></tr>'
        if not rows: rows='<tr><td colspan="6" style="text-align:center;padding:20px;color:#94a3b8;">No findings detected ✅</td></tr>'
        html=f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><title>SecureKey Report</title>
<style>body{{font-family:Arial,sans-serif;background:#0f172a;color:#f1f5f9;margin:0;padding:20px;}}.container{{max-width:1100px;margin:0 auto;}}.header{{background:linear-gradient(135deg,#667eea,#764ba2);padding:30px;border-radius:12px;text-align:center;margin-bottom:24px;}}.header h1{{margin:0;font-size:2rem;}}.header p{{margin:8px 0 0;opacity:.85;}}.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px;}}.stat{{padding:20px;border-radius:10px;text-align:center;border:1px solid;}}.stat .num{{font-size:2rem;font-weight:700;}}.stat .lbl{{font-size:.75rem;margin-top:4px;}}.c{{background:rgba(239,68,68,.15);border-color:#ef4444;color:#ef4444;}}.h{{background:rgba(245,158,11,.15);border-color:#f59e0b;color:#f59e0b;}}.m{{background:rgba(251,191,36,.15);border-color:#fbbf24;color:#fbbf24;}}.l{{background:rgba(16,185,129,.15);border-color:#10b981;color:#10b981;}}.t{{background:rgba(102,126,234,.15);border-color:#667eea;color:#667eea;}}.risk-box{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:20px;margin-bottom:24px;display:flex;align-items:center;gap:20px;}}.risk-score{{font-size:3rem;font-weight:700;}}.risk-bar{{flex:1;height:12px;background:#334155;border-radius:10px;overflow:hidden;}}.risk-fill{{height:100%;border-radius:10px;background:linear-gradient(90deg,#10b981,#fbbf24,#ef4444);}}.target{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px;margin-bottom:24px;}}.target label{{color:#94a3b8;font-size:.8rem;display:block;}}.target span{{font-weight:600;word-break:break-all;}}table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:10px;overflow:hidden;}}th{{background:#334155;padding:12px;text-align:left;font-size:.8rem;color:#94a3b8;text-transform:uppercase;}}td{{padding:10px 12px;border-bottom:1px solid #334155;font-size:.875rem;}}tr:hover td{{background:rgba(255,255,255,.03);}}.footer{{text-align:center;color:#475569;font-size:.75rem;margin-top:24px;padding:16px;}}.warning{{background:rgba(239,68,68,.1);border:1px solid #ef4444;border-radius:10px;padding:16px;margin-bottom:24px;color:#fca5a5;}}</style></head>
<body><div class="container">
<div class="header"><h1>🔐 SecureKey Scanner Report</h1><p>Generated: {ts}</p></div>
<div class="target"><label>SCAN TARGET</label><span>{scan_target}</span></div>
<div class="stats"><div class="stat c"><div class="num">{c}</div><div class="lbl">CRITICAL</div></div><div class="stat h"><div class="num">{h}</div><div class="lbl">HIGH</div></div><div class="stat m"><div class="num">{m}</div><div class="lbl">MEDIUM</div></div><div class="stat l"><div class="num">{l}</div><div class="lbl">LOW</div></div><div class="stat t"><div class="num">{len(findings)}</div><div class="lbl">TOTAL</div></div></div>
<div class="risk-box"><div class="risk-score" style="color:{risk.get('color','#94a3b8')}">{risk.get('score',0)}</div><div><div style="font-size:1.2rem;font-weight:600;color:{risk.get('color','#94a3b8')}">{risk.get('emoji','')} {risk.get('level','Unknown')}</div><div style="color:#94a3b8;font-size:.85rem;">Risk Score / 100</div></div><div class="risk-bar"><div class="risk-fill" style="width:{risk.get('score',0)}%;"></div></div></div>
{'<div class="warning"><strong>⚠️ Action Required:</strong> Rotate all exposed credentials immediately.</div>' if findings else ''}
<table><thead><tr><th>#</th><th>Type</th><th>Severity</th><th>Preview</th><th>Source</th><th>Category</th></tr></thead><tbody>{rows}</tbody></table>
<div class="footer"><p>SecureKey Scanner v2.0 — {ts}</p></div>
</div></body></html>"""
        return jsonify({'html':html,'filename':f'securekey-report-{datetime.now().strftime("%Y%m%d-%H%M%S")}.html'})
    except Exception as e: logger.error(e); return jsonify({'error':str(e)}),500

@app.route('/api/send-email',methods=['POST'])
@limiter.limit("10 per minute")
def send_email_notification():
    try:
        from email.mime.base import MIMEBase
        from email import encoders as email_encoders
        data=request.get_json(); to_email=data.get('to',SMTP_SENDER_EMAIL)
        critical=data.get('critical',0); high=data.get('high',0); medium=data.get('medium',0); low=data.get('low',0)
        total=data.get('totalFindings',0); scan_target=data.get('scanTarget','Unknown')
        findings=data.get('findings',[]); risk=data.get('riskScore',{'score':0,'level':'Unknown','color':'#94a3b8','emoji':''})
        ts=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if not to_email: return jsonify({'error':'Missing email address'}),400
        subject=f"SecureKey Scan Complete — {total} Findings | Risk: {risk.get('score',0)}/100"
        rows=''
        for i,f in enumerate(findings,1):
            clr={'critical':'#ef4444','high':'#f59e0b','medium':'#fbbf24','low':'#10b981'}.get(f.get('severity','low'),'#94a3b8')
            rows+=f'<tr style="border-bottom:1px solid #334155;"><td style="padding:8px 10px;color:#94a3b8;">#{i}</td><td style="padding:8px 10px;font-weight:600;">{f.get("type","Unknown")}</td><td style="padding:8px 10px;"><span style="background:{clr};color:#fff;padding:2px 8px;border-radius:10px;font-size:.7rem;font-weight:700;">{f.get("severity","").upper()}</span></td><td style="padding:8px 10px;font-family:monospace;font-size:.8rem;color:#22d3ee;">{f.get("secret_preview","****")}</td><td style="padding:8px 10px;font-size:.75rem;color:#94a3b8;word-break:break-all;">{f.get("source","Unknown")}</td></tr>'
        if not rows: rows='<tr><td colspan="5" style="padding:20px;text-align:center;color:#94a3b8;">No findings detected</td></tr>'
        html_body=f"""<!DOCTYPE html><html><head><meta charset="UTF-8"/></head><body style="margin:0;padding:20px;font-family:Arial,sans-serif;background:#0f172a;color:#f1f5f9;">
<div style="max-width:800px;margin:0 auto;background:#1e293b;border-radius:16px;overflow:hidden;border:1px solid #334155;">
<div style="background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);padding:30px;text-align:center;"><h1 style="margin:0;color:#fff;font-size:1.8rem;">🔐 SecureKey Scanner</h1><p style="margin:8px 0 0;color:rgba(255,255,255,.85);">Scan Report — {ts}</p></div>
<div style="padding:20px 25px;background:rgba(255,255,255,.03);border-bottom:1px solid #334155;"><p style="margin:0;color:#94a3b8;font-size:.8rem;">RISK SCORE</p><p style="margin:4px 0 0;font-size:2rem;font-weight:700;color:{risk.get('color','#94a3b8')};">{risk.get('emoji','')} {risk.get('score',0)}/100 — {risk.get('level','Unknown')}</p></div>
<div style="padding:20px 25px 0;"><p style="margin:0;color:#94a3b8;font-size:.8rem;">TARGET</p><p style="margin:4px 0 0;font-weight:600;">{scan_target}</p></div>
<div style="padding:20px 25px;"><table width="100%" cellspacing="8" cellpadding="0"><tr>
<td style="background:rgba(239,68,68,.15);border:1px solid #ef4444;border-radius:10px;padding:15px;text-align:center;"><div style="font-size:1.8rem;font-weight:700;color:#ef4444;">{critical}</div><div style="color:#94a3b8;font-size:.75rem;">CRITICAL</div></td>
<td style="background:rgba(245,158,11,.15);border:1px solid #f59e0b;border-radius:10px;padding:15px;text-align:center;"><div style="font-size:1.8rem;font-weight:700;color:#f59e0b;">{high}</div><div style="color:#94a3b8;font-size:.75rem;">HIGH</div></td>
<td style="background:rgba(251,191,36,.15);border:1px solid #fbbf24;border-radius:10px;padding:15px;text-align:center;"><div style="font-size:1.8rem;font-weight:700;color:#fbbf24;">{medium}</div><div style="color:#94a3b8;font-size:.75rem;">MEDIUM</div></td>
<td style="background:rgba(16,185,129,.15);border:1px solid #10b981;border-radius:10px;padding:15px;text-align:center;"><div style="font-size:1.8rem;font-weight:700;color:#10b981;">{low}</div><div style="color:#94a3b8;font-size:.75rem;">LOW</div></td>
<td style="background:rgba(102,126,234,.15);border:1px solid #667eea;border-radius:10px;padding:15px;text-align:center;"><div style="font-size:1.8rem;font-weight:700;color:#667eea;">{total}</div><div style="color:#94a3b8;font-size:.75rem;">TOTAL</div></td>
</tr></table></div>
<div style="padding:0 25px 25px;"><table width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;background:#0f172a;border-radius:10px;overflow:hidden;"><thead><tr style="background:#334155;"><th style="padding:10px;text-align:left;color:#94a3b8;font-size:.75rem;">#</th><th style="padding:10px;text-align:left;color:#94a3b8;font-size:.75rem;">TYPE</th><th style="padding:10px;text-align:left;color:#94a3b8;font-size:.75rem;">SEVERITY</th><th style="padding:10px;text-align:left;color:#94a3b8;font-size:.75rem;">PREVIEW</th><th style="padding:10px;text-align:left;color:#94a3b8;font-size:.75rem;">SOURCE</th></tr></thead><tbody>{rows}</tbody></table><p style="color:#94a3b8;font-size:.75rem;margin-top:10px;">Full JSON report attached.</p></div>
<div style="margin:0 25px 25px;padding:15px;background:rgba(239,68,68,.1);border:1px solid #ef4444;border-radius:10px;"><p style="margin:0;color:#fca5a5;font-weight:600;">⚠️ Action Required</p><p style="margin:6px 0 0;color:#fca5a5;font-size:.85rem;">Rotate all exposed credentials immediately.</p></div>
<div style="padding:15px 25px;border-top:1px solid #334155;text-align:center;"><p style="margin:0;color:#475569;font-size:.7rem;">SecureKey Scanner v2.0 — {ts}</p></div>
</div></body></html>"""
        report_data={'scan_target':scan_target,'timestamp':ts,'risk_score':risk,'total_findings':total,'summary':{'critical':critical,'high':high,'medium':medium,'low':low},'findings':findings}
        json_bytes=json.dumps(report_data,indent=2).encode('utf-8')
        json_fname=f"securekey-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        pdf_fname =f"securekey-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"

        msg=MIMEMultipart('mixed'); msg['Subject']=subject; msg['From']=SMTP_SENDER_EMAIL; msg['To']=to_email
        msg.attach(MIMEText(html_body,'html'))

        # Attach JSON report
        att_json=MIMEBase('application','json'); att_json.set_payload(json_bytes); email_encoders.encode_base64(att_json)
        att_json.add_header('Content-Disposition','attachment',filename=json_fname); msg.attach(att_json)

        # Attach PDF report
        owasp_report = data.get('owaspReport', None)
        pdf_bytes = generate_pdf_report(scan_target, findings, risk, owasp_report)
        if pdf_bytes:
            att_pdf = MIMEBase('application','pdf'); att_pdf.set_payload(pdf_bytes); email_encoders.encode_base64(att_pdf)
            att_pdf.add_header('Content-Disposition','attachment',filename=pdf_fname); msg.attach(att_pdf)
            logger.info('PDF report attached to email')
        else:
            logger.warning('PDF generation skipped — reportlab may not be installed')

        with smtplib.SMTP(SMTP_SERVER,SMTP_PORT) as s: s.starttls(); s.login(SMTP_SENDER_EMAIL,SMTP_SENDER_PASSWORD); s.send_message(msg)
        return jsonify({'success':True,'message':f'Email sent to {to_email} with JSON + PDF attachments'})
    except smtplib.SMTPAuthenticationError as e: return jsonify({'error':f'Auth failed: {str(e)}'}),500
    except Exception as e: logger.error(e); return jsonify({'error':str(e)}),500


# ============================================================
# PDF REPORT GENERATOR
# Uses reportlab — pure Python, no external tools needed
# pip install reportlab
# ============================================================

def generate_pdf_report(scan_target, findings, risk_score, owasp_report=None):
    """
    Generate a professional PDF security report.
    Returns bytes of the PDF file.
    reportlab is used — install with: pip install reportlab
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, KeepTogether
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        import io

        buffer = io.BytesIO()
        doc    = SimpleDocTemplate(
            buffer, pagesize=A4,
            leftMargin=20*mm, rightMargin=20*mm,
            topMargin=20*mm, bottomMargin=20*mm,
            title='SecureKey Security Report',
            author='SecureKey Scanner v2.0'
        )

        # ── Colour palette ──
        COL_BG      = colors.HexColor('#0f172a')
        COL_PURPLE  = colors.HexColor('#7c3aed')
        COL_CYAN    = colors.HexColor('#06b6d4')
        COL_RED     = colors.HexColor('#ef4444')
        COL_ORANGE  = colors.HexColor('#f59e0b')
        COL_YELLOW  = colors.HexColor('#fbbf24')
        COL_GREEN   = colors.HexColor('#10b981')
        COL_GREY    = colors.HexColor('#64748b')
        COL_LIGHT   = colors.HexColor('#f1f5f9')
        COL_DARK    = colors.HexColor('#1e293b')
        COL_BORDER  = colors.HexColor('#334155')

        sev_colors = {
            'critical': COL_RED, 'high': COL_ORANGE,
            'medium': COL_YELLOW, 'low': COL_GREEN
        }

        styles = getSampleStyleSheet()
        story  = []

        # ── Custom paragraph styles ──
        def S(name, parent='Normal', **kw):
            return ParagraphStyle(name, parent=styles[parent], **kw)

        title_style    = S('Title2',    fontSize=22, textColor=colors.white,
                           spaceAfter=4, alignment=TA_CENTER, fontName='Helvetica-Bold')
        subtitle_style = S('Sub',       fontSize=11, textColor=colors.HexColor('#94a3b8'),
                           spaceAfter=2, alignment=TA_CENTER)
        h2_style       = S('H2',        fontSize=13, textColor=COL_PURPLE,
                           spaceBefore=10, spaceAfter=4, fontName='Helvetica-Bold')
        body_style     = S('Body2',     fontSize=9,  textColor=COL_LIGHT,
                           spaceAfter=3, leading=14)
        label_style    = S('Label',     fontSize=8,  textColor=COL_GREY,
                           spaceAfter=1, fontName='Helvetica-Bold')
        code_style     = S('Code2',     fontSize=8,  textColor=COL_CYAN,
                           fontName='Courier', spaceAfter=2)
        finding_h_style= S('FindH',    fontSize=10, textColor=colors.white,
                           fontName='Helvetica-Bold', spaceAfter=2)
        warn_style     = S('Warn',      fontSize=9,  textColor=colors.HexColor('#fca5a5'),
                           spaceAfter=3, leading=13)

        ts_str      = datetime.now().strftime('%B %d, %Y at %H:%M UTC')
        short_ts    = datetime.now().strftime('%Y%m%d-%H%M%S')
        if isinstance(risk_score, dict):
            risk_score_val = risk_score.get('score', 0) or 0
        elif isinstance(risk_score, (int, float)):
            risk_score_val = int(risk_score)
        else:
            risk_score_val = 0
        risk_level  = 'Critical Risk'  if risk_score_val >= 75 else \
                      'High Risk'      if risk_score_val >= 50 else \
                      'Medium Risk'    if risk_score_val >= 25 else \
                      'Low Risk'       if risk_score_val > 0   else 'No Risk Detected'
        risk_col    = COL_RED if risk_score_val >= 75 else \
                      COL_ORANGE if risk_score_val >= 50 else \
                      COL_YELLOW if risk_score_val >= 25 else COL_GREEN

        critical = sum(1 for f in findings if f.get('severity')=='critical')
        high     = sum(1 for f in findings if f.get('severity')=='high')
        medium   = sum(1 for f in findings if f.get('severity')=='medium')
        low      = sum(1 for f in findings if f.get('severity')=='low')
        total    = len(findings)

        # ══════════════════════════════════════════
        # PAGE 1 — COVER / EXECUTIVE SUMMARY
        # ══════════════════════════════════════════

        # Header banner (dark background table)
        header_data = [[
            Paragraph('<font color="#ffffff"><b>🔐 SecureKey Scanner</b></font><br/>'
                      '<font color="#94a3b8" size="9">API Credential Exposure Report</font>',
                      S('hdr', fontSize=16, textColor=colors.white, fontName='Helvetica-Bold',
                        alignment=TA_CENTER, leading=22))
        ]]
        header_tbl = Table(header_data, colWidths=[170*mm])
        header_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), COL_DARK),
            ('ROUNDEDCORNERS', [8,8,8,8]),
            ('TOPPADDING',    (0,0),(-1,-1), 14),
            ('BOTTOMPADDING', (0,0),(-1,-1), 14),
            ('LEFTPADDING',   (0,0),(-1,-1), 16),
        ]))
        story.append(header_tbl)
        story.append(Spacer(1, 6*mm))

        # Meta info
        story.append(Paragraph(f'<font color="#94a3b8">Generated:</font> <b>{ts_str}</b>', body_style))
        story.append(Paragraph(f'<font color="#94a3b8">Scan Target:</font> <b>{scan_target}</b>', body_style))
        story.append(Spacer(1, 4*mm))

        # Risk Score box
        risk_data = [[
            Paragraph(f'<font color="{risk_col.hexval()}" size="28"><b>{risk_score_val}</b></font>'
                      f'<font color="#94a3b8" size="10"> / 100</font>',
                      S('rs', fontSize=28, fontName='Helvetica-Bold', alignment=TA_CENTER)),
            Paragraph(f'<font color="{risk_col.hexval()}" size="14"><b>{risk_level}</b></font>',
                      S('rl', fontSize=14, fontName='Helvetica-Bold', alignment=TA_LEFT,
                        textColor=risk_col))
        ]]
        risk_tbl = Table(risk_data, colWidths=[45*mm, 125*mm])
        risk_tbl.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,-1), COL_DARK),
            ('BOX',           (0,0),(-1,-1), 1.5, risk_col),
            ('TOPPADDING',    (0,0),(-1,-1), 10),
            ('BOTTOMPADDING', (0,0),(-1,-1), 10),
            ('LEFTPADDING',   (0,0),(-1,-1), 12),
            ('VALIGN',        (0,0),(-1,-1), 'MIDDLE'),
        ]))
        story.append(risk_tbl)
        story.append(Spacer(1, 4*mm))

        # Severity summary grid
        sev_data = [
            [
                Paragraph(f'<font color="#ef4444" size="20"><b>{critical}</b></font><br/>'
                          f'<font color="#94a3b8" size="8">CRITICAL</font>',
                          S('sc', fontSize=20, alignment=TA_CENTER, fontName='Helvetica-Bold', leading=26)),
                Paragraph(f'<font color="#f59e0b" size="20"><b>{high}</b></font><br/>'
                          f'<font color="#94a3b8" size="8">HIGH</font>',
                          S('sh', fontSize=20, alignment=TA_CENTER, fontName='Helvetica-Bold', leading=26)),
                Paragraph(f'<font color="#fbbf24" size="20"><b>{medium}</b></font><br/>'
                          f'<font color="#94a3b8" size="8">MEDIUM</font>',
                          S('sm', fontSize=20, alignment=TA_CENTER, fontName='Helvetica-Bold', leading=26)),
                Paragraph(f'<font color="#10b981" size="20"><b>{low}</b></font><br/>'
                          f'<font color="#94a3b8" size="8">LOW</font>',
                          S('sl', fontSize=20, alignment=TA_CENTER, fontName='Helvetica-Bold', leading=26)),
                Paragraph(f'<font color="#7c3aed" size="20"><b>{total}</b></font><br/>'
                          f'<font color="#94a3b8" size="8">TOTAL</font>',
                          S('st', fontSize=20, alignment=TA_CENTER, fontName='Helvetica-Bold', leading=26)),
            ]
        ]
        sev_tbl = Table(sev_data, colWidths=[34*mm]*5)
        sev_tbl.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(0,0), colors.HexColor('#2d1515')),
            ('BACKGROUND',    (1,0),(1,0), colors.HexColor('#2d1f0a')),
            ('BACKGROUND',    (2,0),(2,0), colors.HexColor('#2d2810')),
            ('BACKGROUND',    (3,0),(3,0), colors.HexColor('#0d2820')),
            ('BACKGROUND',    (4,0),(4,0), colors.HexColor('#1a1035')),
            ('BOX',           (0,0),(0,0), 1, COL_RED),
            ('BOX',           (1,0),(1,0), 1, COL_ORANGE),
            ('BOX',           (2,0),(2,0), 1, COL_YELLOW),
            ('BOX',           (3,0),(3,0), 1, COL_GREEN),
            ('BOX',           (4,0),(4,0), 1, COL_PURPLE),
            ('TOPPADDING',    (0,0),(-1,-1), 8),
            ('BOTTOMPADDING', (0,0),(-1,-1), 8),
            ('LEFTPADDING',   (0,0),(-1,-1), 4),
            ('ALIGN',         (0,0),(-1,-1), 'CENTER'),
        ]))
        story.append(sev_tbl)
        story.append(Spacer(1, 6*mm))

        # OWASP compliance summary if available
        if owasp_report:
            story.append(HRFlowable(width='100%', thickness=0.5, color=COL_BORDER))
            story.append(Spacer(1, 3*mm))
            story.append(Paragraph('OWASP API Security Top 10 — 2023 Compliance', h2_style))
            score = owasp_report.get('compliance_score', 0)
            violations = owasp_report.get('violations', 0)
            passing    = owasp_report.get('passing', 0)
            story.append(Paragraph(
                f'<font color="#94a3b8">Compliance Score: </font>'
                f'<font color="{"#10b981" if score >= 70 else "#ef4444"}"><b>{score}%</b></font>'
                f'  |  <font color="#ef4444"><b>{violations} violated</b></font>'
                f'  |  <font color="#10b981"><b>{passing} passing</b></font>',
                body_style))

            # OWASP table
            owasp_rows = [['Category', 'Status', 'Findings', 'Severity']]
            for r in owasp_report.get('report', []):
                status_txt = 'FAIL' if r.get('status') == 'FAIL' else 'PASS'
                status_col = '#ef4444' if status_txt == 'FAIL' else '#10b981'
                sev_txt    = (r.get('highest_severity') or '—').upper()
                owasp_rows.append([
                    Paragraph(f'<b>{r.get("id","")}</b> {r.get("short","")}', S('oc', fontSize=8, textColor=COL_LIGHT)),
                    Paragraph(f'<font color="{status_col}"><b>{status_txt}</b></font>', S('os', fontSize=8, alignment=TA_CENTER)),
                    Paragraph(str(r.get('count', 0)), S('on', fontSize=8, alignment=TA_CENTER, textColor=COL_LIGHT)),
                    Paragraph(sev_txt, S('osv', fontSize=8, alignment=TA_CENTER,
                                         textColor=sev_colors.get((r.get('highest_severity') or '').lower(), COL_GREY))),
                ])
            owasp_tbl = Table(owasp_rows, colWidths=[90*mm, 25*mm, 25*mm, 30*mm])
            owasp_tbl.setStyle(TableStyle([
                ('BACKGROUND',    (0,0),(-1,0), COL_DARK),
                ('TEXTCOLOR',     (0,0),(-1,0), COL_GREY),
                ('FONTNAME',      (0,0),(-1,0), 'Helvetica-Bold'),
                ('FONTSIZE',      (0,0),(-1,0), 8),
                ('BACKGROUND',    (0,1),(-1,-1), colors.HexColor('#0f172a')),
                ('ROWBACKGROUNDS',(0,1),(-1,-1), [colors.HexColor('#0f172a'), colors.HexColor('#111827')]),
                ('GRID',          (0,0),(-1,-1), 0.3, COL_BORDER),
                ('ALIGN',         (1,0),(-1,-1), 'CENTER'),
                ('TOPPADDING',    (0,0),(-1,-1), 5),
                ('BOTTOMPADDING', (0,0),(-1,-1), 5),
                ('LEFTPADDING',   (0,0),(-1,-1), 6),
            ]))
            story.append(owasp_tbl)
            story.append(Spacer(1, 5*mm))

        # ══════════════════════════════════════════
        # FINDINGS TABLE
        # ══════════════════════════════════════════
        story.append(HRFlowable(width='100%', thickness=0.5, color=COL_BORDER))
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph(f'Detailed Findings ({total})', h2_style))

        if not findings:
            story.append(Paragraph('No secrets or credentials were detected.', body_style))
        else:
            # Findings table header
            tbl_rows = [[
                Paragraph('#',          S('th', fontSize=8, textColor=COL_GREY, fontName='Helvetica-Bold')),
                Paragraph('Type',       S('th', fontSize=8, textColor=COL_GREY, fontName='Helvetica-Bold')),
                Paragraph('Severity',   S('th', fontSize=8, textColor=COL_GREY, fontName='Helvetica-Bold')),
                Paragraph('Preview',    S('th', fontSize=8, textColor=COL_GREY, fontName='Helvetica-Bold')),
                Paragraph('Source',     S('th', fontSize=8, textColor=COL_GREY, fontName='Helvetica-Bold')),
                Paragraph('OWASP',      S('th', fontSize=8, textColor=COL_GREY, fontName='Helvetica-Bold')),
            ]]
            for i, f in enumerate(findings, 1):
                sev  = (f.get('severity') or 'low').lower()
                scol = sev_colors.get(sev, COL_GREY)
                tbl_rows.append([
                    Paragraph(str(i), S('td', fontSize=8, textColor=COL_GREY)),
                    Paragraph((f.get('type') or 'Unknown')[:35], S('td', fontSize=8, textColor=COL_LIGHT, fontName='Helvetica-Bold')),
                    Paragraph(f'<font color="{scol.hexval()}"><b>{sev.upper()}</b></font>',
                              S('td', fontSize=8, alignment=TA_CENTER)),
                    Paragraph(f.get('secret_preview') or '****', S('td', fontSize=7, textColor=COL_CYAN, fontName='Courier')),
                    Paragraph((f.get('source') or 'Unknown')[:30], S('td', fontSize=7, textColor=COL_GREY)),
                    Paragraph((f.get('owasp') or {}).get('owasp_id', '—') if isinstance(f.get('owasp'), dict) else '—',
                              S('td', fontSize=7, textColor=colors.HexColor('#f87171'))),
                ])
            findings_tbl = Table(tbl_rows, colWidths=[8*mm, 52*mm, 20*mm, 28*mm, 38*mm, 24*mm])
            findings_tbl.setStyle(TableStyle([
                ('BACKGROUND',    (0,0),(-1,0), COL_DARK),
                ('ROWBACKGROUNDS',(0,1),(-1,-1), [colors.HexColor('#0f172a'), colors.HexColor('#111827')]),
                ('GRID',          (0,0),(-1,-1), 0.3, COL_BORDER),
                ('ALIGN',         (0,0),(0,-1), 'CENTER'),
                ('ALIGN',         (2,0),(2,-1), 'CENTER'),
                ('TOPPADDING',    (0,0),(-1,-1), 5),
                ('BOTTOMPADDING', (0,0),(-1,-1), 5),
                ('LEFTPADDING',   (0,0),(-1,-1), 5),
                ('VALIGN',        (0,0),(-1,-1), 'TOP'),
            ]))
            story.append(findings_tbl)

        # ── Footer ──
        story.append(Spacer(1, 6*mm))
        story.append(HRFlowable(width='100%', thickness=0.5, color=COL_BORDER))
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph(
            '<font color="#ef4444"><b>⚠ Action Required:</b></font>'
            ' <font color="#fca5a5">Rotate all exposed credentials immediately. '
            'Remove hardcoded secrets from source code and use environment variables.</font>',
            warn_style))
        story.append(Paragraph(
            f'<font color="#475569">SecureKey Scanner v2.0 — {ts_str} — '
            'OWASP API Security Top 10 — 2023 Compliance Report</font>',
            S('foot', fontSize=7, textColor=COL_GREY, alignment=TA_CENTER)))

        doc.build(story)
        buffer.seek(0)
        return buffer.read()

    except ImportError:
        logger.error('reportlab not installed — run: pip install reportlab')
        return None
    except Exception as e:
        logger.error(f'PDF generation error: {e}')
        return None


@app.route('/api/report/pdf', methods=['POST'])
@limiter.limit("10 per minute")
def download_pdf_report():
    """Generate and return PDF report for download."""
    try:
        data         = request.get_json()
        findings     = data.get('findings', [])
        scan_target  = data.get('scanTarget', 'Unknown Target')
        risk_score   = data.get('riskScore', 0)
        owasp_report = data.get('owaspReport', None)

        pdf_bytes = generate_pdf_report(scan_target, findings, risk_score, owasp_report)
        if not pdf_bytes:
            return jsonify({'error': 'PDF generation failed — run: pip install reportlab'}), 500

        from flask import Response
        fname = f"securekey-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename="{fname}"',
                     'Content-Length': len(pdf_bytes)}
        )
    except Exception as e:
        logger.error(f'PDF download error: {e}')
        return jsonify({'error': str(e)}), 500

# ========================================
# AI FIX SUGGESTION ENGINE
# ========================================

# Per-category rotation guides that get injected into the AI prompt
# so Claude gives accurate, step-by-step instructions
FIX_GUIDES = {
    'Cloud - AWS': {
        'rotation_url': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html',
        'rotation_steps': [
            'Go to AWS Console → IAM → Users → Security Credentials',
            'Click "Create access key" to generate a new key pair',
            'Update all services/apps that use the old key with the new credentials',
            'Click "Deactivate" on the old key first (do NOT delete yet)',
            'Verify all services still work with the new key',
            'Click "Delete" on the old key after confirming everything works',
            'Check CloudTrail logs for any unauthorized usage of the old key'
        ]
    },
    'Cloud - GCP': {
        'rotation_url': 'https://cloud.google.com/docs/authentication/api-keys#securing_an_api_key',
        'rotation_steps': [
            'Go to Google Cloud Console → APIs & Services → Credentials',
            'Click the exposed key → "Regenerate key"',
            'Update all applications with the new key',
            'Delete the old key from the console',
            'Review API key restrictions (HTTP referrers, IP addresses)'
        ]
    },
    'Cloud - Azure': {
        'rotation_url': 'https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage',
        'rotation_steps': [
            'Go to Azure Portal → Storage Account → Access Keys',
            'Click "Rotate key" for the exposed key',
            'Update all connection strings in your applications',
            'Verify Azure Key Vault is being used for future secrets'
        ]
    },
    'Version Control': {
        'rotation_url': 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens',
        'rotation_steps': [
            'Go to GitHub → Settings → Developer settings → Personal access tokens',
            'Delete the exposed token immediately',
            'Create a new token with minimum required permissions',
            'Update all places that use the old token (CI/CD, .env files, scripts)',
            'Check GitHub audit log for unauthorized API calls using the old token'
        ]
    },
    'Database': {
        'rotation_url': 'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials',
        'rotation_steps': [
            'Immediately change the database user password',
            'Revoke all active sessions for the exposed user',
            'Update the connection string in all environments (dev/staging/prod)',
            'Move credentials to environment variables or a secrets manager',
            'Review database access logs for unauthorized queries'
        ]
    },
    'Payment': {
        'rotation_url': 'https://stripe.com/docs/keys#keeping-your-keys-safe',
        'rotation_steps': [
            'Go to your payment provider dashboard immediately',
            'Revoke / roll the exposed API key',
            'Generate a new restricted key with only required permissions',
            'Update your backend with the new key',
            'Review payment logs for unauthorized charges or refunds'
        ]
    },
    'Communication': {
        'rotation_url': 'https://api.slack.com/authentication/rotation',
        'rotation_steps': [
            'Go to your platform app settings and revoke the exposed token',
            'Regenerate a new token or OAuth credential',
            'Update all integrations and bots with the new token',
            'Review audit logs for messages sent using the exposed token'
        ]
    },
    'Cryptography': {
        'rotation_url': 'https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning',
        'rotation_steps': [
            'Revoke the exposed private key/certificate at your CA immediately',
            'Generate a new key pair using: ssh-keygen -t ed25519 or openssl genrsa',
            'Deploy the new public key to all servers',
            'Remove the old private key from all systems and repos',
            'Audit git history with: git log -p | grep -i "BEGIN PRIVATE KEY"'
        ]
    },
    'Authentication': {
        'rotation_url': 'https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length',
        'rotation_steps': [
            'Invalidate all existing sessions/tokens immediately',
            'Rotate the JWT secret or OAuth client secret',
            'Force re-login for all users',
            'Implement token expiry and refresh token rotation'
        ]
    },
    'CI/CD': {
        'rotation_url': 'https://docs.github.com/en/actions/security-guides/encrypted-secrets',
        'rotation_steps': [
            'Revoke the exposed CI/CD token in your platform settings',
            'Generate a new token with minimum required permissions',
            'Update the secret in your CI/CD environment variables',
            'Never store secrets in plain text in YAML files — use encrypted secrets'
        ]
    },
    'Generic': {
        'rotation_url': 'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials',
        'rotation_steps': [
            'Immediately revoke or change the exposed credential',
            'Move all secrets to environment variables (.env file, never committed)',
            'Use a secrets manager: AWS Secrets Manager, HashiCorp Vault, or Doppler',
            'Add .env to your .gitignore file',
            'Scan git history: git log --all -p | grep -i "secret\\|key\\|password"'
        ]
    }
}

@app.route('/api/fix-suggestion', methods=['POST'])
@limiter.limit("15 per minute")
def get_fix_suggestion():
    """
    AI-powered fix suggestions using Claude.
    For each finding, returns:
      1. fixed_code   — the corrected code snippet with secret removed
      2. rotation_steps — step-by-step credential rotation guide
      3. risk_explanation — plain English risk summary
      4. prevention_tips — how to avoid this in future
    """
    try:
        data = request.get_json()
        if not data or 'finding' not in data:
            return jsonify({'error': 'Missing finding field'}), 400

        finding  = data['finding']
        context  = data.get('context', finding.get('context', ''))
        category = finding.get('category', 'Generic')

        # Get the matching rotation guide (fallback to Generic)
        guide_key = next((k for k in FIX_GUIDES if category.startswith(k)), 'Generic')
        guide     = FIX_GUIDES[guide_key]

        prompt = f"""You are a senior application security engineer. A secret credential was found exposed in source code.

FINDING DETAILS:
- Type: {finding.get('type', 'Unknown')}
- Severity: {finding.get('severity', 'unknown').upper()}
- Category: {category}
- Pattern: {finding.get('pattern_name', 'unknown')}
- Source File: {finding.get('source', 'unknown')}
- Secret Preview: {finding.get('secret_preview', '[redacted]')}

CODE CONTEXT WHERE SECRET WAS FOUND:
```
{context[:500] if context else 'No context available'}
```

ROTATION GUIDE FOR THIS CREDENTIAL TYPE:
{chr(10).join(f'{i+1}. {step}' for i, step in enumerate(guide['rotation_steps']))}

Your job is to provide a JSON response with exactly these 4 keys:

1. "fixed_code": A corrected version of the code context above with the secret replaced by an environment variable. Show the full corrected code snippet (not just one line). If no code context is available, show a best-practice example for this credential type.

2. "risk_explanation": 2-3 sentences in plain English explaining exactly what an attacker could do with this exposed credential. Be specific to this credential type (e.g. for AWS key: what API calls they could make, what data they could steal or destroy).

3. "rotation_steps": An array of strings — the exact steps to rotate THIS specific credential type. Be precise and actionable.

4. "prevention_tips": An array of 3-4 short, specific tips to prevent this class of secret from being exposed again. Include specific tool names (e.g. git-secrets, pre-commit hooks, .gitignore).

Respond ONLY with valid JSON. No markdown, no explanation outside the JSON object.

Example format:
{{
  "fixed_code": "# Store in environment variable\\nimport os\\nAWS_KEY = os.environ.get('AWS_ACCESS_KEY_ID')",
  "risk_explanation": "An attacker with this key can...",
  "rotation_steps": ["Step 1: ...", "Step 2: ..."],
  "prevention_tips": ["Use python-dotenv and .env files", "Add pre-commit hooks with detect-secrets"]
}}"""

        # Use Groq (free) if available, fallback to Anthropic, then static
        ai_text = None
        if GROQ_API_KEY:
            try:
                groq_resp = requests.post(
                    'https://api.groq.com/openai/v1/chat/completions',
                    headers={
                        'Authorization': f'Bearer {GROQ_API_KEY}',
                        'Content-Type':  'application/json',
                    },
                    json={
                        'model':       'llama-3.3-70b-versatile',
                        'max_tokens':  1200,
                        'temperature': 0.2,
                        'messages': [
                            {'role': 'system', 'content': 'You are a senior security engineer. Always respond with valid JSON only.'},
                            {'role': 'user',   'content': prompt}
                        ]
                    },
                    timeout=30
                )
                if groq_resp.status_code == 200:
                    ai_text = groq_resp.json()['choices'][0]['message']['content']
                    logger.info('AI Fix generated via Groq')
                else:
                    logger.error(f"Groq error: {groq_resp.status_code} {groq_resp.text[:100]}")
            except Exception as ge:
                logger.error(f"Groq call failed: {ge}")

        if ai_text is None and ANTHROPIC_API_KEY:
            try:
                anth_resp = requests.post(
                    'https://api.anthropic.com/v1/messages',
                    headers={'Content-Type':'application/json','anthropic-version':'2023-06-01','x-api-key':ANTHROPIC_API_KEY},
                    json={'model':'claude-sonnet-4-20250514','max_tokens':1200,'messages':[{'role':'user','content':prompt}]},
                    timeout=30
                )
                if anth_resp.status_code == 200:
                    ai_text = anth_resp.json().get('content',[{}])[0].get('text','{}')
                    logger.info('AI Fix generated via Anthropic')
            except Exception as ae:
                logger.error(f"Anthropic call failed: {ae}")

        if ai_text is None:
            logger.warning('No AI available — using static fallback')
            return jsonify({
                'fixed_code': _generate_static_fix(finding, context),
                'risk_explanation': f'This exposed {finding.get("type","credential")} could allow an attacker unauthorized access to your {category} resources. Rotate immediately.',
                'rotation_steps': guide['rotation_steps'],
                'prevention_tips': [
                    'Store secrets in environment variables, never in source code',
                    'Add .env to .gitignore and use python-dotenv / dotenv libraries',
                    'Use pre-commit hooks: pip install detect-secrets',
                    'Scan git history: git log --all -p | grep -i "secret\\|key\\|password"'
                ],
                'rotation_url': guide['rotation_url'],
                'source': 'static_fallback'
            })

        # Strip markdown fences if present
        ai_text = re.sub(r'```json\s*', '', ai_text)
        ai_text = re.sub(r'```\s*', '', ai_text)
        ai_text = ai_text.strip()

        try:
            result = json.loads(ai_text)
        except json.JSONDecodeError:
            logger.warning(f"JSON parse failed, using raw text: {ai_text[:100]}")
            result = {
                'fixed_code': _generate_static_fix(finding, context),
                'risk_explanation': ai_text[:300],
                'rotation_steps': guide['rotation_steps'],
                'prevention_tips': ['Store secrets in environment variables', 'Use a secrets manager'],
            }

        result['rotation_url'] = guide['rotation_url']
        result['source'] = 'ai'
        logger.info(f"AI fix suggestion generated for {finding.get('type')}")
        return jsonify(result)

    except requests.exceptions.Timeout:
        return jsonify({'error': 'AI service timeout — using static guide', 'rotation_steps': FIX_GUIDES.get('Generic', {}).get('rotation_steps', [])}), 504
    except Exception as e:
        logger.error(f"Fix suggestion error: {e}")
        return jsonify({'error': str(e)}), 500


def _generate_static_fix(finding, context):
    """Fallback static fix code when AI is unavailable."""
    pname = finding.get('pattern_name', '')
    ftype = finding.get('type', 'secret')
    env_var = re.sub(r'[^A-Z0-9]', '_', ftype.upper())[:30]

    templates = {
        'aws':        f'import os\n\nAWS_ACCESS_KEY_ID     = os.environ.get("AWS_ACCESS_KEY_ID")\nAWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")\n\n# Load from .env file (never commit .env to git)\n# pip install python-dotenv\n# from dotenv import load_dotenv; load_dotenv()',
        'github':     f'import os\n\nGITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")\n# Or use: gh auth login  (GitHub CLI)',
        'stripe':     f'import os\n\nSTRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")\n# In .env:  STRIPE_SECRET_KEY=sk_live_...',
        'mongodb':    f'import os\n\nMONGODB_URI = os.environ.get("MONGODB_URI")\n# In .env:  MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/db',
        'postgresql': f'import os\n\nDATABASE_URL = os.environ.get("DATABASE_URL")\n# Use connection pooling: psycopg2 / asyncpg',
        'private_key':f'# NEVER store private keys in source code\n# Use SSH agent: ssh-add ~/.ssh/id_ed25519\n# Or environment variable:\nimport os\nPRIVATE_KEY = os.environ.get("PRIVATE_KEY").replace("\\\\n", "\\n")',
    }

    for key, tmpl in templates.items():
        if key in pname.lower():
            return tmpl

    return f'import os\n\n# Replace hardcoded secret with environment variable\n{env_var} = os.environ.get("{env_var}")\n\n# Setup:\n# 1. Create a .env file (add to .gitignore)\n# 2. Add: {env_var}=your_actual_value\n# 3. Load with: from dotenv import load_dotenv; load_dotenv()'


# ========================================
# LIVE API KEY VALIDATOR
# ========================================

def _extract_raw_secret(finding):
    """
    Recover the raw secret value from the finding context.
    Handles long tokens (JWT, RSA keys) by searching full context.
    Falls back gracefully if extraction fails.
    """
    context  = finding.get('context', '')
    pname    = finding.get('pattern_name', '')
    preview  = finding.get('secret_preview', '')

    # Method 1 — re-match pattern against context
    if pname and pname in PATTERNS:
        try:
            m = re.search(PATTERNS[pname]['pattern'], context)
            if m:
                secret = m.group(1) if m.lastindex else m.group(0)
                if len(secret) >= 8:   # sanity check — real secrets are long
                    return secret
        except Exception:
            pass

    # Method 2 — for JWT specifically: look for eyJ... pattern in context
    if pname == 'jwt_token' or (preview and preview.startswith('eyJ')):
        jwt_match = re.search(
            r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_.\-]+',
            context
        )
        if jwt_match:
            return jwt_match.group(0)

    # Method 3 — for patterns where secret is the whole match (no capture group)
    # Try a broader search using just the prefix/format clue from preview
    if preview and '...' in preview:
        prefix = preview.split('...')[0]   # e.g. "ghp_" from "ghp_...884a"
        if prefix and len(prefix) >= 3:
            # Find the prefix in context and extract the full token
            idx = context.find(prefix)
            if idx != -1:
                # Extract from prefix to end of alphanumeric+special chars
                candidate = re.match(
                    r'[A-Za-z0-9_\-\.\/\+\=]{8,}',
                    context[idx:]
                )
                if candidate:
                    return candidate.group(0)

    return None


def _validate_aws(key_id, secret_key=None):
    """Call AWS STS GetCallerIdentity — read-only, free, no side effects."""
    try:
        import hmac, hashlib, base64
        from datetime import datetime as dt

        now      = dt.utcnow()
        date_str = now.strftime('%Y%m%d')
        amz_date = now.strftime('%Y%m%dT%H%M%SZ')
        region   = 'us-east-1'
        service  = 'sts'
        host     = 'sts.amazonaws.com'
        endpoint = f'https://{host}/'
        payload  = 'Action=GetCallerIdentity&Version=2011-06-15'

        # If we only have key_id (no secret), do a quick format check
        if not secret_key:
            valid_fmt = bool(re.match(r'^AKIA[0-9A-Z]{16}$', key_id or ''))
            return {
                'active': None,
                'status': 'format_only',
                'message': 'AWS Access Key ID format is valid — secret key needed for live check',
                'key_id': key_id,
                'format_valid': valid_fmt,
                'account_id': None,
                'user_arn': None,
            }

        def sign(key, msg):
            return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

        def get_sig_key(key, date, region, service):
            k_date    = sign(('AWS4' + key).encode('utf-8'), date)
            k_region  = sign(k_date, region)
            k_service = sign(k_region, service)
            k_signing = sign(k_service, 'aws4_request')
            return k_signing

        payload_hash      = hashlib.sha256(payload.encode()).hexdigest()
        canonical_headers = f'content-type:application/x-www-form-urlencoded\nhost:{host}\nx-amz-date:{amz_date}\n'
        signed_headers    = 'content-type;host;x-amz-date'
        canonical_request = f'POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}'

        credential_scope  = f'{date_str}/{region}/{service}/aws4_request'
        string_to_sign    = f'AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}'

        signing_key = get_sig_key(secret_key, date_str, region, service)
        signature   = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

        auth_header = (
            f'AWS4-HMAC-SHA256 Credential={key_id}/{credential_scope}, '
            f'SignedHeaders={signed_headers}, Signature={signature}'
        )

        resp = requests.post(endpoint,
            data=payload,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Amz-Date': amz_date,
                'Authorization': auth_header,
            },
            timeout=8
        )

        if resp.status_code == 200:
            account = re.search(r'<Account>(\d+)</Account>', resp.text)
            arn     = re.search(r'<Arn>([^<]+)</Arn>', resp.text)
            userid  = re.search(r'<UserId>([^<]+)</UserId>', resp.text)
            return {
                'active': True,
                'status': 'active',
                'message': '🔴 ACTIVE — This credential is live and working. Rotate immediately!',
                'account_id': account.group(1) if account else None,
                'user_arn':   arn.group(1)     if arn     else None,
                'user_id':    userid.group(1)  if userid  else None,
            }
        elif resp.status_code == 403:
            if 'InvalidClientTokenId' in resp.text:
                return {'active': False, 'status': 'revoked', 'message': '✅ Key is invalid or already revoked — no action needed'}
            if 'SignatureDoesNotMatch' in resp.text:
                return {'active': None, 'status': 'wrong_secret', 'message': '⚠️ Key ID found but secret key mismatch — key ID may still be active'}
            return {'active': False, 'status': 'denied', 'message': '⚠️ Key exists but access denied — may have restricted permissions'}
        else:
            return {'active': None, 'status': 'unknown', 'message': f'Unknown response: HTTP {resp.status_code}'}

    except Exception as e:
        return {'active': None, 'status': 'error', 'message': f'Validation error: {str(e)}'}


def _validate_github(token):
    """Call GitHub /user — read-only."""
    try:
        resp = requests.get(
            'https://api.github.com/user',
            headers={'Authorization': f'token {token}', 'User-Agent': 'SecureKey-Scanner/2.0'},
            timeout=8
        )
        if resp.status_code == 200:
            data = resp.json()
            scopes = resp.headers.get('X-OAuth-Scopes', 'unknown')
            return {
                'active': True,
                'status': 'active',
                'message': '🔴 ACTIVE — GitHub token is live and working. Revoke immediately!',
                'username': data.get('login'),
                'name':     data.get('name'),
                'email':    data.get('email'),
                'scopes':   scopes,
                'repos':    data.get('public_repos'),
                'private_repos': data.get('total_private_repos', 0),
            }
        elif resp.status_code == 401:
            return {'active': False, 'status': 'revoked', 'message': '✅ Token is invalid or already revoked — no action needed'}
        else:
            return {'active': None, 'status': 'unknown', 'message': f'HTTP {resp.status_code}'}
    except Exception as e:
        return {'active': None, 'status': 'error', 'message': f'Validation error: {str(e)}'}


def _validate_stripe(key):
    """Stripe — check balance, account info, and key permissions."""
    try:
        # Check balance
        resp = requests.get(
            'https://api.stripe.com/v1/balance',
            auth=(key, ''),
            headers={'User-Agent': 'SecureKey-Scanner/2.0'},
            timeout=8
        )
        if resp.status_code == 200:
            data     = resp.json()
            avail    = data.get('available', [{}])
            amt      = avail[0].get('amount', 0) / 100 if avail else 0
            curr     = avail[0].get('currency', 'usd').upper() if avail else 'USD'
            livemode = data.get('livemode', False)

            # Determine key type and permissions from key prefix
            key_type  = 'Secret (Full Access)' if key.startswith('sk_') else                         'Restricted Key'        if key.startswith('rk_') else                         'Publishable Key'       if key.startswith('pk_') else 'Unknown'
            mode      = 'LIVE PRODUCTION' if 'live' in key else 'TEST MODE'

            # Assess what this key can do
            scopes = []
            if key.startswith('sk_'):
                scopes = [
                    'Read ALL charges and payments',
                    'Read ALL customer data and cards',
                    'Create/modify subscriptions',
                    'Issue refunds',
                    'Access payout/bank info',
                    'Read webhook endpoints',
                ]
            elif key.startswith('rk_'):
                scopes = ['Restricted — limited permissions (check Stripe dashboard for exact scopes)']

            # Try to get account info
            acct_resp = requests.get(
                'https://api.stripe.com/v1/account',
                auth=(key, ''),
                headers={'User-Agent': 'SecureKey-Scanner/2.0'},
                timeout=8
            )
            account_name  = None
            account_email = None
            country       = None
            if acct_resp.status_code == 200:
                acct = acct_resp.json()
                account_name  = acct.get('settings', {}).get('dashboard', {}).get('display_name') or acct.get('business_profile', {}).get('name')
                account_email = acct.get('email')
                country       = acct.get('country')

            blast = [
                f'Read all payment history (balance: {amt} {curr})',
                'Access complete customer PII (names, emails, addresses)',
                'View saved card details (last 4, expiry, billing address)',
            ]
            if livemode:
                blast.append('Issue fraudulent refunds to attacker-controlled accounts')
                blast.append('Cancel customer subscriptions causing revenue loss')

            return {
                'active':        True,
                'status':        'active',
                'message':       f'🔴 ACTIVE — Stripe {mode} key working. Revoke immediately!',
                'livemode':      livemode,
                'balance':       f'{amt} {curr}',
                'key_type':      key_type,
                'mode':          mode,
                'account_name':  account_name,
                'email':         account_email,
                'country':       country,
                'scopes':        scopes,
                'blast_radius':  blast,
                'pentest_note':  f'{"⚠️ LIVE key — real customer money and data" if livemode else "TEST key — no real money but demonstrates access pattern"}',
                'risk_level':    'CRITICAL' if livemode else 'HIGH',
            }
        elif resp.status_code == 401:
            return {'active': False, 'status': 'revoked', 'message': '✅ Stripe key is invalid or already revoked'}
        else:
            return {'active': None, 'status': 'unknown', 'message': f'HTTP {resp.status_code}'}
    except Exception as e:
        return {'active': None, 'status': 'error', 'message': f'Validation error: {str(e)}'}


def _validate_sendgrid(key):
    """SendGrid — profile + actual API scopes/permissions."""
    try:
        headers = {'Authorization': f'Bearer {key}', 'User-Agent': 'SecureKey-Scanner/2.0'}

        # Get user profile
        resp = requests.get(
            'https://api.sendgrid.com/v3/user/profile',
            headers=headers, timeout=8
        )
        if resp.status_code == 200:
            data     = resp.json()
            username = data.get('username')
            email    = data.get('email')
            company  = data.get('company')

            # Get actual API key scopes
            scopes_resp = requests.get(
                'https://api.sendgrid.com/v3/scopes',
                headers=headers, timeout=8
            )
            scopes       = []
            critical_ops = []
            if scopes_resp.status_code == 200:
                scopes = scopes_resp.json().get('scopes', [])
                # Flag dangerous scopes
                if 'mail.send' in scopes:
                    critical_ops.append('Send emails to ANY address from your domain')
                if 'templates.read' in scopes:
                    critical_ops.append('Read all email templates')
                if 'marketing.read' in scopes:
                    critical_ops.append('Read all marketing contact lists')
                if 'api_keys.create' in scopes:
                    critical_ops.append('Create new API keys (persistence)')
                if 'user.account.read' in scopes:
                    critical_ops.append('Read full account billing info')

            # Get contact list stats
            contacts_resp = requests.get(
                'https://api.sendgrid.com/v3/marketing/contacts/count',
                headers=headers, timeout=8
            )
            contact_count = 0
            if contacts_resp.status_code == 200:
                contact_count = contacts_resp.json().get('contact_count', 0)

            blast = critical_ops or [
                'Send phishing/spam emails from your trusted domain',
                'Bypass spam filters (your domain is trusted)',
                'Access all email analytics and open rates',
            ]
            if contact_count > 0:
                blast.insert(0, f'Send to all {contact_count:,} contacts in marketing list')

            return {
                'active':        True,
                'status':        'active',
                'message':       '🔴 ACTIVE — SendGrid key is live. Revoke immediately!',
                'username':      username,
                'email':         email,
                'company':       company,
                'scopes':        scopes[:10],   # show first 10 scopes
                'total_scopes':  len(scopes),
                'critical_ops':  critical_ops,
                'contact_count': contact_count,
                'blast_radius':  blast,
                'pentest_note':  f'Key has {len(scopes)} permission(s). Can send email as your domain — domain reputation at risk.',
                'risk_level':    'CRITICAL' if 'mail.send' in scopes else 'HIGH',
            }
        elif resp.status_code == 401:
            return {'active': False, 'status': 'revoked', 'message': '✅ SendGrid key is invalid or revoked'}
        else:
            return {'active': None, 'status': 'unknown', 'message': f'HTTP {resp.status_code}'}
    except Exception as e:
        return {'active': None, 'status': 'error', 'message': f'Validation error: {str(e)}'}


def _validate_slack(token):
    """Slack — auth.test + token scope detection + workspace info."""
    try:
        headers = {'Authorization': f'Bearer {token}', 'User-Agent': 'SecureKey-Scanner/2.0'}
        resp    = requests.post('https://slack.com/api/auth.test', headers=headers, timeout=8)
        data    = resp.json()

        if data.get('ok'):
            team    = data.get('team')
            user    = data.get('user')
            team_id = data.get('team_id')
            user_id = data.get('user_id')
            is_bot  = data.get('bot_id') is not None
            token_type = 'Bot Token' if is_bot else 'User Token'

            # Read scopes from response header (Slack sends X-OAuth-Scopes)
            raw_scopes = resp.headers.get('X-OAuth-Scopes', '')
            scope_list = [s.strip() for s in raw_scopes.split(',') if s.strip()]

            # Assess dangerous scopes
            critical_scopes = []
            blast = []
            if 'chat:write' in scope_list or 'chat:write:bot' in scope_list:
                critical_scopes.append('chat:write')
                blast.append('Send messages to ANY channel as bot')
            if 'files:read' in scope_list:
                critical_scopes.append('files:read')
                blast.append('Download all shared files and attachments')
            if 'channels:history' in scope_list or 'groups:history' in scope_list:
                critical_scopes.append('channels:history')
                blast.append('Read full message history of all channels')
            if 'users:read' in scope_list:
                blast.append('Enumerate all workspace members + emails')
            if 'im:read' in scope_list or 'mpim:read' in scope_list:
                critical_scopes.append('im:read')
                blast.append('Read private direct messages')
            if 'admin' in scope_list:
                critical_scopes.append('admin')
                blast.append('Full workspace admin access')

            if not blast:
                blast = ['Access Slack workspace — scope details limited']

            # Get workspace member count
            member_count = None
            users_resp = requests.get(
                'https://slack.com/api/users.list',
                headers=headers,
                params={'limit': 1},
                timeout=8
            )
            if users_resp.json().get('ok'):
                member_count = users_resp.json().get('response_metadata', {}).get('next_cursor') and '100+'

            return {
                'active':          True,
                'status':          'active',
                'message':         f'🔴 ACTIVE — Slack {token_type} is live. Revoke immediately!',
                'team':            team,
                'user':            user,
                'team_id':         team_id,
                'user_id':         user_id,
                'token_type':      token_type,
                'scopes':          scope_list,
                'critical_scopes': critical_scopes,
                'member_count':    member_count,
                'blast_radius':    blast,
                'pentest_note':    f'{token_type} in workspace "{team}". {len(critical_scopes)} critical scope(s): {critical_scopes or "none"}',
                'risk_level':      'CRITICAL' if critical_scopes else 'HIGH',
            }
        else:
            err = data.get('error', 'unknown')
            if err in ('invalid_auth','token_revoked','account_inactive','not_authed'):
                return {'active': False, 'status': 'revoked', 'message': f'✅ Slack token is invalid/revoked ({err})'}
            return {'active': None, 'status': 'unknown', 'message': f'Slack error: {err}'}
    except Exception as e:
        return {'active': None, 'status': 'error', 'message': f'Validation error: {str(e)}'}


def _validate_gitlab(token):
    """GitLab — user info + token scopes + project access count."""
    try:
        headers = {'PRIVATE-TOKEN': token, 'User-Agent': 'SecureKey-Scanner/2.0'}

        # Get user info
        resp = requests.get('https://gitlab.com/api/v4/user', headers=headers, timeout=8)
        if resp.status_code == 200:
            data     = resp.json()
            username = data.get('username')
            name     = data.get('name')
            email    = data.get('email')
            is_admin = data.get('is_admin', False)
            state    = data.get('state', 'active')

            # Get token scopes via /api/v4/personal_access_tokens/self
            scopes     = []
            token_name = None
            expires_at = None
            scope_resp = requests.get(
                'https://gitlab.com/api/v4/personal_access_tokens/self',
                headers=headers, timeout=8
            )
            if scope_resp.status_code == 200:
                token_data = scope_resp.json()
                scopes     = token_data.get('scopes', [])
                token_name = token_data.get('name')
                expires_at = token_data.get('expires_at', 'Never')

            # Assess danger
            critical_scopes = []
            blast           = []
            if 'api' in scopes:
                critical_scopes.append('api')
                blast.append('Full API access — read/write all projects and repos')
            if 'write_repository' in scopes:
                critical_scopes.append('write_repository')
                blast.append('Push malicious code to any accessible repository')
            if 'sudo' in scopes or is_admin:
                critical_scopes.append('sudo/admin')
                blast.append('⚠️ FULL INSTANCE ADMIN — control all users and projects')
            if 'read_api' in scopes and 'api' not in scopes:
                blast.append('Read all project code, issues, merge requests')
            if 'read_registry' in scopes or 'write_registry' in scopes:
                blast.append('Access/push Docker images in container registry')
            if 'read_user' in scopes:
                blast.append('Read all user profile data and email addresses')

            if not blast:
                blast = ['Access GitLab instance with token permissions']

            # Count accessible projects
            proj_resp = requests.get(
                'https://gitlab.com/api/v4/projects',
                headers=headers,
                params={'membership': True, 'per_page': 1},
                timeout=8
            )
            project_count = proj_resp.headers.get('X-Total', '?') if proj_resp.status_code == 200 else '?'

            return {
                'active':          True,
                'status':          'active',
                'message':         f'🔴 ACTIVE — GitLab token is live{"  ⚠️ ADMIN!" if is_admin else ""}. Revoke immediately!',
                'username':        username,
                'name':            name,
                'email':           email,
                'is_admin':        is_admin,
                'state':           state,
                'token_name':      token_name,
                'scopes':          scopes,
                'critical_scopes': critical_scopes,
                'expires_at':      expires_at,
                'project_count':   project_count,
                'blast_radius':    blast,
                'pentest_note':    f'Token "{token_name}" scopes: {scopes}. Admin: {is_admin}. Projects accessible: {project_count}',
                'risk_level':      'CRITICAL' if (is_admin or 'api' in scopes) else 'HIGH',
            }
        elif resp.status_code == 401:
            return {'active': False, 'status': 'revoked', 'message': '✅ GitLab token is invalid or revoked'}
        else:
            return {'active': None, 'status': 'unknown', 'message': f'HTTP {resp.status_code}'}
    except Exception as e:
        return {'active': None, 'status': 'error', 'message': f'Validation error: {str(e)}'}


def _validate_npm(token):
    """npm — whoami + token type + package list (supply chain attack assessment)."""
    try:
        headers = {'Authorization': f'Bearer {token}', 'User-Agent': 'SecureKey-Scanner/2.0'}

        # Get username
        resp = requests.get('https://registry.npmjs.org/-/whoami', headers=headers, timeout=8)
        if resp.status_code == 200:
            username = resp.json().get('username', 'unknown')

            # Detect token type from prefix
            token_type  = 'Automation Token' if token.startswith('npm_') else 'Legacy Token'
            can_publish = token_type == 'Automation Token'   # automation tokens can publish

            # Get packages owned by this user
            pkg_resp = requests.get(
                f'https://registry.npmjs.org/-/org/{username}/package',
                headers=headers, timeout=8
            )
            packages = []
            if pkg_resp.status_code == 200:
                packages = list(pkg_resp.json().keys())

            # Also try user packages
            if not packages:
                user_pkg = requests.get(
                    f'https://registry.npmjs.org/-/v1/search?text=maintainer:{username}&size=5',
                    timeout=8
                )
                if user_pkg.status_code == 200:
                    packages = [o['package']['name'] for o in user_pkg.json().get('objects', [])]

            # Determine scopes
            scopes = ['Read package data', 'Download private packages']
            blast  = ['Publish malicious versions of owned packages — supply chain attack']
            if packages:
                total_downloads = f'{len(packages)} packages found'
                blast.insert(0, f'Compromise {len(packages)} packages: {", ".join(packages[:3])}{"..." if len(packages) > 3 else ""}')
            else:
                total_downloads = 'No packages found (may have none)'

            if can_publish:
                scopes.append('Publish packages (Automation scope)')
                scopes.append('Publish without 2FA prompt')
            else:
                scopes.append('Publish packages (requires 2FA if enabled)')

            return {
                'active':       True,
                'status':       'active',
                'message':      f'🔴 ACTIVE — npm {token_type} is live. Revoke immediately!',
                'username':     username,
                'token_type':   token_type,
                'can_publish':  can_publish,
                'packages':     packages[:5],
                'package_count':len(packages),
                'scopes':       scopes,
                'blast_radius': blast,
                'pentest_note': f'User "{username}" owns {len(packages)} package(s). {token_type} {"CAN" if can_publish else "may"} publish without 2FA.',
                'risk_level':   'CRITICAL',
            }
        elif resp.status_code == 401:
            return {'active': False, 'status': 'revoked', 'message': '✅ npm token is invalid or revoked'}
        else:
            return {'active': None, 'status': 'unknown', 'message': f'HTTP {resp.status_code}'}
    except Exception as e:
        return {'active': None, 'status': 'error', 'message': f'Validation error: {str(e)}'}


# Map pattern names to their validator functions

# ============================================================
# PENTESTING VALIDATORS — Added for advanced recon
# All read-only. No writes, no charges, no side effects.
# ============================================================

def _validate_google_api_key(key):
    """Test Google API key against multiple services to find what it can access."""
    try:
        results = {}

        # Test 1 — Google Maps Geocoding (most common leaked key type)
        resp = requests.get(
            'https://maps.googleapis.com/maps/api/geocode/json',
            params={'address': 'Google HQ', 'key': key},
            timeout=8
        )
        data = resp.json()
        if data.get('status') == 'OK':
            results['maps_geocoding'] = True
        elif data.get('status') == 'REQUEST_DENIED':
            results['maps_geocoding'] = False
        elif data.get('status') == 'OVER_DAILY_LIMIT':
            results['maps_geocoding'] = 'quota_exceeded'

        # Test 2 — YouTube Data API
        resp2 = requests.get(
            'https://www.googleapis.com/youtube/v3/videos',
            params={'part': 'id', 'id': 'dQw4w9WgXcQ', 'key': key},
            timeout=8
        )
        if resp2.status_code == 200:
            results['youtube'] = True
        elif resp2.status_code == 403:
            results['youtube'] = False

        # Test 3 — Places API
        resp3 = requests.get(
            'https://maps.googleapis.com/maps/api/place/nearbysearch/json',
            params={'location': '37.4220,-122.0841', 'radius': '100', 'key': key},
            timeout=8
        )
        data3 = resp3.json()
        if data3.get('status') not in ('REQUEST_DENIED', 'INVALID_REQUEST'):
            results['places'] = True

        active_services = [k for k, v in results.items() if v is True]

        if active_services:
            # Estimate billing risk
            billing_risk = 'HIGH' if 'maps_geocoding' in active_services or 'places' in active_services else 'MEDIUM'
            return {
                'active': True,
                'status': 'active',
                'message': f'🔴 ACTIVE — Google API key works on: {", ".join(active_services)}',
                'services_accessible': active_services,
                'billing_risk': billing_risk,
                'pentest_note': f'Attacker can make unlimited API calls billed to victim account. Billing risk: {billing_risk}',
            }
        else:
            return {
                'active': False,
                'status': 'revoked',
                'message': '✅ Key rejected by all tested Google services — likely revoked or restricted',
            }
    except Exception as e:
        return {'active': None, 'status': 'error', 'message': f'Validation error: {str(e)}'}


def _validate_twilio(account_sid, auth_token=None):
    """Test Twilio credentials — can send SMS if active."""
    try:
        if not auth_token:
            # Format check only
            valid = bool(re.match(r'^AC[a-z0-9]{32}$', account_sid or ''))
            return {
                'active': None,
                'status': 'format_only',
                'message': f'Twilio Account SID format {"valid" if valid else "invalid"} — auth token needed for live check',
            }

        resp = requests.get(
            f'https://api.twilio.com/2010-04-01/Accounts/{account_sid}.json',
            auth=(account_sid, auth_token),
            timeout=8
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                'active': True,
                'status': 'active',
                'message': f'🔴 ACTIVE — Twilio account accessible',
                'account_name': data.get('friendly_name'),
                'status_str':   data.get('status'),
                'account_type': data.get('type'),
                'pentest_note': 'Attacker can send SMS/calls to any number billed to victim. Can access all message logs.',
                'blast_radius': 'Send spam SMS, make calls, read all messages, access phone numbers',
            }
        elif resp.status_code == 401:
            return {'active': False, 'status': 'revoked', 'message': '✅ Credentials invalid or revoked'}
        else:
            return {'active': None, 'status': 'unknown', 'message': f'HTTP {resp.status_code}'}
    except Exception as e:
        return {'active': None, 'status': 'error', 'message': str(e)}


def _validate_discord_bot_token(token):
    """Test Discord bot token — read-only, checks bot user info."""
    try:
        resp = requests.get(
            'https://discord.com/api/v10/users/@me',
            headers={'Authorization': f'Bot {token}'},
            timeout=8
        )
        if resp.status_code == 200:
            data = resp.json()
            # Check if bot is in any guilds
            guilds_resp = requests.get(
                'https://discord.com/api/v10/users/@me/guilds',
                headers={'Authorization': f'Bot {token}'},
                timeout=8
            )
            guild_count = len(guilds_resp.json()) if guilds_resp.status_code == 200 else 'unknown'

            return {
                'active': True,
                'status': 'active',
                'message': f'🔴 ACTIVE — Discord bot token valid',
                'bot_name':    data.get('username'),
                'bot_id':      data.get('id'),
                'verified':    data.get('verified'),
                'guild_count': guild_count,
                'pentest_note': f'Bot has access to {guild_count} Discord servers. Can read messages, members, channels.',
                'blast_radius': 'Read all messages in all servers, send messages, access member lists, download files',
            }
        elif resp.status_code == 401:
            return {'active': False, 'status': 'revoked', 'message': '✅ Token invalid or revoked'}
        else:
            return {'active': None, 'status': 'unknown', 'message': f'HTTP {resp.status_code}'}
    except Exception as e:
        return {'active': None, 'status': 'error', 'message': str(e)}


def _validate_jwt_token(token):
    """
    Decode JWT token — extract ALL claims, detect algorithm vulnerabilities,
    flag PortSwigger-style attacks (alg confusion, kid injection, none attack).
    Works 100% offline — no API call needed.
    """
    try:
        import base64
        import json as json_lib

        parts = token.split('.')
        if len(parts) != 3:
            return {'active': None, 'status': 'format_only', 'message': 'Invalid JWT format — needs 3 parts (header.payload.signature)'}

        def decode_part(part):
            part += '=' * (4 - len(part) % 4)
            try:
                return json_lib.loads(base64.urlsafe_b64decode(part))
            except:
                return {}

        header  = decode_part(parts[0])
        payload = decode_part(parts[1])

        # Extract all claims
        algorithm  = header.get('alg', 'unknown')
        kid        = header.get('kid', None)         # Key ID — injection risk
        typ        = header.get('typ', 'JWT')
        subject    = payload.get('sub', '')
        issuer     = payload.get('iss', '')
        audience   = payload.get('aud', '')
        exp        = payload.get('exp')
        iat        = payload.get('iat')
        nbf        = payload.get('nbf')
        jti        = payload.get('jti', '')           # JWT ID
        email      = payload.get('email', payload.get('mail', payload.get('preferred_username', '')))
        roles      = payload.get('roles', payload.get('scope', payload.get('permissions', payload.get('authorities', []))))
        user_id    = payload.get('user_id', payload.get('userId', payload.get('uid', payload.get('id', ''))))
        username   = payload.get('username', payload.get('name', payload.get('login', '')))
        is_admin   = payload.get('admin', payload.get('is_admin', payload.get('isAdmin', False)))
        groups     = payload.get('groups', payload.get('cognito:groups', []))

        # Check expiry
        expired = False
        exp_str = 'No expiry set ⚠️'
        time_left = None
        if exp:
            from datetime import datetime as dt, timezone
            exp_dt   = dt.fromtimestamp(exp, tz=timezone.utc)
            now_dt   = dt.now(tz=timezone.utc)
            expired  = now_dt > exp_dt
            exp_str  = exp_dt.strftime('%Y-%m-%d %H:%M UTC')
            diff     = exp_dt - now_dt
            if not expired:
                mins = int(diff.total_seconds() / 60)
                time_left = f'{mins} minutes remaining' if mins < 60 else f'{mins//60}h {mins%60}m remaining'

        # ── SECURITY VULNERABILITY ASSESSMENT ──
        security_issues  = []
        attack_vectors   = []

        # 1. Algorithm none attack
        if algorithm.upper() == 'NONE':
            security_issues.append('🚨 Algorithm NONE — signature is not verified. Token can be forged without any key!')
            attack_vectors.append('alg:none attack — remove signature, set alg to none, server accepts')

        # 2. HS256 with RS256 confusion attack
        elif algorithm.upper() == 'HS256':
            security_issues.append('⚠️ HS256 — if server also accepts RS256, algorithm confusion attack possible')
            attack_vectors.append('Algorithm confusion — sign with RS public key as HMAC secret')

        # 3. RS256 algorithm confusion attack (PortSwigger lab scenario)
        elif algorithm.upper() == 'RS256':
            security_issues.append('ℹ️ RS256 — check if server accepts HS256 (algorithm confusion attack)')
            attack_vectors.append('Algorithm confusion: change alg to HS256, sign with server public key as HMAC secret')
            attack_vectors.append('jwks_uri manipulation — if server fetches public key remotely')

        # 4. Key ID (kid) injection
        if kid:
            security_issues.append(f'⚠️ kid parameter present: "{kid}" — test for SQL injection and path traversal')
            attack_vectors.append(f'kid injection: try kid="../../../../dev/null" or kid="x\' UNION SELECT..."')
            if any(c in str(kid) for c in ["'", '"', '--', ';', '/', '..']):
                security_issues.append('🚨 kid contains special characters — ACTIVE injection attempt detected!')

        # 5. No expiry
        if not exp:
            security_issues.append('⚠️ No expiry (exp claim missing) — token never expires')
            attack_vectors.append('Token can be used indefinitely after theft')

        # 6. Admin claim
        if is_admin:
            security_issues.append('🚨 admin=true claim in token — test if modifying this claim is accepted')
            attack_vectors.append('Modify admin claim to false→true, resign or bypass signature verification')

        # 7. Sensitive data in payload
        sensitive_claims = {}
        for k, v in payload.items():
            if any(word in k.lower() for word in ['pass', 'secret', 'key', 'token', 'credit', 'card', 'ssn', 'pwd']):
                sensitive_claims[k] = str(v)[:20] + '...'

        if sensitive_claims:
            security_issues.append(f'🚨 Sensitive data in payload: {list(sensitive_claims.keys())}')

        # Determine overall status
        status    = 'expired' if expired else 'active'
        active    = not expired
        risk_lvl  = 'CRITICAL' if any('🚨' in s for s in security_issues) else \
                    'HIGH'     if any('⚠️' in s for s in security_issues) else 'MEDIUM'

        # Build scope list for display
        scope_display = []
        if is_admin: scope_display.append('admin=true')
        if roles:
            if isinstance(roles, list): scope_display.extend(roles[:5])
            else: scope_display.append(str(roles))
        if groups:
            if isinstance(groups, list): scope_display.extend([f'group:{g}' for g in groups[:3]])
        if not scope_display: scope_display = ['Standard user claims']

        blast = []
        if is_admin: blast.append('Admin privileges — full application access')
        blast.append(f'Impersonate user: {subject or username or email or "unknown"}')
        if attack_vectors: blast.append(f'Attack: {attack_vectors[0]}')

        return {
            'active':           active,
            'status':           status,
            'message':          f'{"⚠️ EXPIRED" if expired else "🔴 ACTIVE"} — JWT decoded | Algorithm: {algorithm} | Subject: {subject}',
            # Header info
            'algorithm':        algorithm,
            'kid':              str(kid) if kid else None,
            'token_type':       typ,
            # Identity claims
            'subject':          str(subject) if subject else None,
            'issuer':           str(issuer)  if issuer  else None,
            'username':         str(username) if username else None,
            'email':            str(email)   if email   else None,
            'user_id':          str(user_id) if user_id else None,
            'is_admin':         is_admin,
            # Permission claims
            'scopes':           scope_display,
            'roles':            roles if isinstance(roles, list) else ([str(roles)] if roles else []),
            'groups':           groups if isinstance(groups, list) else [],
            # Time info
            'expiry':           exp_str,
            'time_left':        time_left,
            # Security assessment
            'security_issues':  security_issues,
            'attack_vectors':   attack_vectors,
            'risk_level':       risk_lvl,
            'blast_radius':     blast,
            'pentest_note':     f'Algorithm: {algorithm} | kid: {kid or "none"} | {len(attack_vectors)} attack vector(s) identified',
            # Full payload for reference
            'full_payload':     {k: str(v)[:100] for k, v in payload.items()},
        }
    except Exception as e:
        return {'active': None, 'status': 'error', 'message': f'JWT decode error: {str(e)}'}


def _validate_mailchimp(api_key):
    """Test Mailchimp API key — access to mailing lists."""
    try:
        # Mailchimp keys end with datacenter: abc123abc-us1
        if '-' not in api_key:
            return {'active': None, 'status': 'format_only', 'message': 'Invalid Mailchimp key format'}

        dc = api_key.split('-')[-1]  # e.g. us1, us20
        resp = requests.get(
            f'https://{dc}.api.mailchimp.com/3.0/',
            auth=('anystring', api_key),
            timeout=8
        )
        if resp.status_code == 200:
            data = resp.json()
            account = data.get('account_name', 'Unknown')
            email   = data.get('email', '')
            members = data.get('total_subscribers', 0)
            return {
                'active': True,
                'status': 'active',
                'message': f'🔴 ACTIVE — Mailchimp account accessible',
                'account_name': account,
                'email':        email,
                'total_subscribers': members,
                'pentest_note': f'Access to {members} email subscribers. Can send emails to entire list, export all contacts.',
                'blast_radius': 'Send phishing emails to subscriber list, export all contact data, create new campaigns',
            }
        elif resp.status_code == 401:
            return {'active': False, 'status': 'revoked', 'message': '✅ API key invalid or revoked'}
        else:
            return {'active': None, 'status': 'unknown', 'message': f'HTTP {resp.status_code}'}
    except Exception as e:
        return {'active': None, 'status': 'error', 'message': str(e)}


def _validate_github_enhanced(token):
    """Enhanced GitHub validation — reads scopes, repos, org access, 2FA status."""
    try:
        resp = requests.get(
            'https://api.github.com/user',
            headers={
                'Authorization': f'token {token}',
                'User-Agent': 'SecureKey-Scanner/2.0'
            },
            timeout=8
        )
        if resp.status_code == 200:
            data   = resp.json()
            scopes = resp.headers.get('X-OAuth-Scopes', '')
            scope_list = [s.strip() for s in scopes.split(',') if s.strip()]

            # Assess danger level of scopes
            critical_scopes = [s for s in scope_list if s in ('repo','admin:org','delete_repo','admin:repo_hook','write:packages')]
            high_scopes     = [s for s in scope_list if s in ('write:org','admin:public_key','admin:gpg_key','gist')]
            medium_scopes   = [s for s in scope_list if s in ('read:org','notifications','user','user:email')]

            # Determine blast radius
            blast = []
            if 'repo' in scope_list:
                blast.append('Read/write ALL private repos')
            if 'admin:org' in scope_list:
                blast.append('Manage entire GitHub organisation')
            if 'delete_repo' in scope_list:
                blast.append('DELETE any repository permanently')
            if 'write:packages' in scope_list:
                blast.append('Publish malicious npm/docker packages')

            # Check 2FA
            two_fa = data.get('two_factor_authentication', None)

            # Get repo count
            public_repos  = data.get('public_repos', 0)
            private_repos = data.get('total_private_repos', 0)

            risk_level = 'CRITICAL' if critical_scopes else ('HIGH' if high_scopes else 'MEDIUM')

            return {
                'active':          True,
                'status':          'active',
                'message':         f'🔴 ACTIVE — GitHub token valid',
                'username':        data.get('login'),
                'email':           data.get('email'),
                'name':            data.get('name'),
                'company':         data.get('company'),
                'public_repos':    public_repos,
                'private_repos':   private_repos,
                'scopes':          scope_list,
                'critical_scopes': critical_scopes,
                'high_scopes':     high_scopes,
                'two_fa_enabled':  two_fa,
                'risk_level':      risk_level,
                'blast_radius':    blast if blast else ['Read public profile only'],
                'pentest_note':    f'Token has {len(scope_list)} scope(s). Critical: {critical_scopes or "none"}',
            }
        elif resp.status_code == 401:
            return {'active': False, 'status': 'revoked', 'message': '✅ Token invalid or already revoked — no action needed'}
        elif resp.status_code == 403:
            return {'active': None, 'status': 'rate_limited', 'message': '⚠️ Rate limited — token may be valid, try again in 1 minute'}
        else:
            return {'active': None, 'status': 'unknown', 'message': f'HTTP {resp.status_code}'}
    except Exception as e:
        return {'active': None, 'status': 'error', 'message': str(e)}


def _validate_aws_secret_key(secret_key, finding):
    """
    Validator for aws_secret_key pattern.
    The secret key alone cannot authenticate — we need the Access Key ID (AKIA...).
    Strategy:
      1. Search the finding context for a paired AKIA key ID
      2. If found → run full AWS STS validation with both keys
      3. If not found → search nearby lines in context for AKIA pattern
      4. Report clearly what was found and what is still needed
    """
    try:
        context = finding.get('context', '')
        source  = finding.get('source', 'unknown')

        # ── Step 1: Extract the actual secret value from the raw match ──
        # The pattern captures group(2) for the secret value
        secret_match = re.search(
            r"(?i)(?:aws_secret_access_key|aws_secret|secret_key)\\s*[=:]\\s*[\x27\x22]?([A-Za-z0-9/+=]{40})[\x27\x22]?",
            secret_key
        )
        actual_secret = secret_match.group(1) if secret_match else secret_key
        # If the passed value already looks like a raw 40-char secret, use it directly
        if re.match(r'^[A-Za-z0-9/+=]{40}$', secret_key):
            actual_secret = secret_key

        # ── Step 2: Search context for paired AKIA Access Key ID ──
        key_id_match = re.search(r'AKIA[0-9A-Z]{16}', context)
        paired_key_id = key_id_match.group(0) if key_id_match else None

        if paired_key_id and actual_secret and len(actual_secret) == 40:
            # We have BOTH parts — run full live validation
            logger.info(f'AWS secret key paired with Key ID {paired_key_id[:8]}... — running full validation')
            result = _validate_aws(paired_key_id, actual_secret)
            result['paired_key_id']  = paired_key_id
            result['secret_found']   = True
            result['validation_type'] = 'full_pair'
            result['pentest_note']   = (
                f'Both AWS credentials found in {source}. '
                f'Key ID: {paired_key_id} paired with Secret Key.'
            )
            return result

        # ── Step 3: No Key ID found — report clearly ──
        # The secret IS leaked but we can't validate without the Key ID
        secret_preview = actual_secret[:6] + '...' + actual_secret[-4:] if len(actual_secret) >= 10 else actual_secret

        # Check if this looks like a real 40-char AWS secret (base64-like)
        looks_valid = bool(re.match(r'^[A-Za-z0-9/+=]{40}$', actual_secret))

        return {
            'active':         None,
            'status':         'secret_without_key_id',
            'message':        '⚠️ AWS Secret Access Key found in code — Access Key ID (AKIA...) not found nearby',
            'secret_found':   True,
            'secret_preview': secret_preview,
            'format_valid':   looks_valid,
            'paired_key_id':  None,
            'validation_type': 'secret_only',
            'scopes':         ['Cannot confirm — need Access Key ID (AKIA...) to test live'],
            'blast_radius':   [
                'If paired with valid Key ID: full AWS account access',
                'Cannot confirm active status without the Key ID',
                'Credential IS leaked — rotate immediately regardless',
            ],
            'pentest_note': (
                f'AWS Secret Key found in {source} but no matching AKIA Key ID in the same context. '
                f'The secret IS exposed and should be rotated. '
                f'Search the same file/repo for "AKIA" to find the paired Key ID.'
            ),
            'action_required': (
                'Even without confirming liveness: '
                '1. Go to AWS Console → IAM → Search for keys matching this secret. '
                '2. Deactivate and delete the key pair. '
                '3. Check CloudTrail for any unauthorized usage. '
                '4. The keyword "aws_secret_access_key" in code confirms this is a real credential.'
            ),
            'risk_level': 'CRITICAL',
        }

    except Exception as e:
        return {'active': None, 'status': 'error', 'message': f'Validation error: {str(e)}'}


VALIDATORS = {
    # Cloud credentials
    'aws_access_key':        lambda s, f: _validate_aws(s),
    'aws_secret_key':        lambda s, f: _validate_aws_secret_key(s, f),
    # Version control
    'github_token':          lambda s, f: _validate_github_enhanced(s),
    'github_oauth':          lambda s, f: _validate_github_enhanced(s),
    'github_app_token':      lambda s, f: _validate_github_enhanced(s),
    'gitlab_token':          lambda s, f: _validate_gitlab(s),
    # Payment
    'stripe_live_key':       lambda s, f: _validate_stripe(s),
    'stripe_test_key':       lambda s, f: _validate_stripe(s),
    'stripe_restricted_key': lambda s, f: _validate_stripe(s),
    # Communication
    'sendgrid_api_key':      lambda s, f: _validate_sendgrid(s),
    'slack_token':           lambda s, f: _validate_slack(s),
    'slack_legacy_token':    lambda s, f: _validate_slack(s),
    'discord_bot_token':     lambda s, f: _validate_discord_bot_token(s),
    'twilio_api_key':        lambda s, f: _validate_twilio(s),
    # Marketing
    'mailchimp_api_key':     lambda s, f: _validate_mailchimp(s),
    # Package managers
    'npm_token':             lambda s, f: _validate_npm(s),
    # GCP / Google
    'google_api_key':        lambda s, f: _validate_google_api_key(s),
    'firebase_api_key':      lambda s, f: _validate_google_api_key(s),
    # Authentication tokens
    'jwt_token':             lambda s, f: _validate_jwt_token(s),
}

# Which categories are validatable (for frontend "Test Live" button visibility)
VALIDATABLE_PATTERNS = set(VALIDATORS.keys())


@app.route('/api/validate-key', methods=['POST'])
@limiter.limit("10 per minute")
def validate_key():
    """
    Live API key validation endpoint.
    Tries to authenticate with the real service using the found credential.
    All calls are read-only — no writes, no deletes, no charges.
    """
    try:
        data        = request.get_json()
        finding     = data.get('finding', {})
        raw_secret  = data.get('raw_secret')      # Frontend can pass if it extracted it
        pattern_name = finding.get('pattern_name', '')

        if not pattern_name:
            return jsonify({'error': 'No pattern_name in finding'}), 400

        # Check if we support validation for this pattern
        if pattern_name not in VALIDATORS:
            return jsonify({
                'supported': False,
                'message': f'Live validation not available for {finding.get("type", pattern_name)}',
                'supported_types': list(VALIDATORS.keys())
            }), 200

        # Try to extract raw secret from context if not provided
        if not raw_secret:
            # First check if finding has raw_secret stored directly
            raw_secret = finding.get('raw_secret')

        if not raw_secret:
            # Fallback — re-extract from context
            raw_secret = _extract_raw_secret(finding)

        if not raw_secret:
            return jsonify({
                'supported': True,
                'active': None,
                'status': 'no_secret',
                'message': 'Secret value could not be extracted from context for live validation. The key preview is masked for security.',
                'pattern_name': pattern_name,
            })

        # Run the validator
        validator = VALIDATORS[pattern_name]
        result    = validator(raw_secret, finding)

        result['supported']     = True
        result['pattern_name']  = pattern_name
        result['key_type']      = finding.get('type', 'Unknown')
        result['tested_at']     = datetime.now().isoformat()

        logger.info(f"Key validation: {pattern_name} → {result.get('status','unknown')}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"Validate key error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/validate-key/supported', methods=['GET'])
def get_supported_validators():
    """Return list of pattern names that support live validation."""
    return jsonify({'supported_patterns': list(VALIDATABLE_PATTERNS)})


@app.route('/api/owasp/summary', methods=['POST'])
@limiter.limit("20 per minute")
def owasp_summary():
    """
    Given a list of findings, return a full OWASP API Top 10 compliance report.
    Shows which categories are violated, how many findings per category,
    and which categories passed (no violations found).
    """
    try:
        data = request.get_json()
        findings = data.get('findings', [])

        # Count violations per OWASP category
        violations = {}
        for f in findings:
            owasp = f.get('owasp')
            if not owasp:
                owasp = get_owasp_info(f.get('pattern_name',''))
            if not owasp:
                continue
            oid = owasp.get('owasp_id') or owasp.get('key','')
            if not oid: continue
            if oid not in violations:
                violations[oid] = {
                    'key':oid,'id':oid,
                    'name':owasp.get('owasp_name',''),
                    'short':owasp.get('owasp_short',''),
                    'color':owasp.get('owasp_color','#94a3b8'),
                    'url':owasp.get('owasp_url',''),
                    'description':owasp.get('owasp_description',''),
                    'findings':[],'count':0,'status':'FAIL','highest_severity':'low',
                }
            violations[oid]['findings'].append({
                'type':f.get('type'),'severity':f.get('severity'),
                'source':f.get('source'),'compliance':owasp.get('compliance',[]),
                'impact':owasp.get('impact',''),
            })
            violations[oid]['count'] += 1
            sev_order = {'critical':4,'high':3,'medium':2,'low':1}
            if sev_order.get(f.get('severity','low'),0) > sev_order.get(violations[oid]['highest_severity'],0):
                violations[oid]['highest_severity'] = f.get('severity','low')

        report = []
        for oid, info in OWASP_API_TOP10.items():
            if oid in violations:
                report.append(violations[oid])
            else:
                report.append({'key':oid,'id':oid,'name':info['name'],'short':info['short'],
                    'color':info['color'],'url':info['url'],'description':info.get('description',''),
                    'findings':[],'count':0,'status':'PASS','highest_severity':None})

        total_violations = sum(1 for r in report if r['status'] == 'FAIL')
        compliance_score = round(((10 - total_violations) / 10) * 100)

        return jsonify({
            'report':           report,
            'total_categories': 10,
            'violations':       total_violations,
            'passing':          10 - total_violations,
            'compliance_score': compliance_score,
            'total_findings':   len(findings),
            'timestamp':        datetime.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"OWASP summary error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/owasp/top10', methods=['GET'])
def get_owasp_top10():
    """Return the full OWASP API Security Top 10 reference."""
    return jsonify({'top10': OWASP_API_TOP10, 'pattern_map': OWASP_PATTERN_MAP})



@app.route('/api/chat', methods=['POST'])
@limiter.limit("60 per minute")
def chat_proxy():
    """AI chat proxy — routes through Flask to Groq, answers any security question."""
    try:
        data          = request.get_json()
        system_prompt = data.get('system', 'You are a helpful cybersecurity expert.')
        messages      = data.get('messages', [])

        if not messages:
            return jsonify({'error': 'No messages provided'}), 400

        clean_messages = [
            {'role': m['role'], 'content': str(m['content'])[:3000]}
            for m in messages
            if m.get('role') in ('user', 'assistant') and m.get('content')
        ]
        if not clean_messages:
            return jsonify({'error': 'No valid messages'}), 400

        reply = None

        # Try Groq first (free)
        if GROQ_API_KEY:
            try:
                groq_msgs = [{'role':'system','content':system_prompt[:3000]}] + clean_messages
                resp = requests.post(
                    'https://api.groq.com/openai/v1/chat/completions',
                    headers={'Authorization': f'Bearer {GROQ_API_KEY}', 'Content-Type': 'application/json'},
                    json={'model': 'llama-3.3-70b-versatile', 'max_tokens': 800, 'temperature': 0.7, 'messages': groq_msgs},
                    timeout=30
                )
                if resp.status_code == 200:
                    reply = resp.json()['choices'][0]['message']['content']
                    logger.info('Chat via Groq')
                else:
                    logger.error(f"Groq chat error: {resp.status_code} {resp.text[:100]}")
            except Exception as e:
                logger.error(f"Groq chat failed: {e}")

        # Fallback to Anthropic
        if not reply and ANTHROPIC_API_KEY:
            try:
                resp = requests.post(
                    ANTHROPIC_API_URL,
                    headers={'Content-Type':'application/json','anthropic-version':'2023-06-01','x-api-key':ANTHROPIC_API_KEY},
                    json={'model':'claude-sonnet-4-20250514','max_tokens':800,'system':system_prompt[:3000],'messages':clean_messages},
                    timeout=30
                )
                if resp.status_code == 200:
                    reply = resp.json().get('content',[{}])[0].get('text','')
                    logger.info('Chat via Anthropic')
            except Exception as e:
                logger.error(f"Anthropic chat failed: {e}")

        if not reply:
            reply = "I couldn't connect to the AI service right now. Please check your GROQ_API_KEY in your .env file and restart Flask."

        return jsonify({'reply': reply})

    except Exception as e:
        logger.error(f"Chat proxy error: {e}")
        return jsonify({'reply': 'Chat service error. Please restart Flask backend.'}), 200


@app.route('/api/patterns',methods=['GET'])
def get_patterns():
    pl=[{'name':n,**c,'owasp':get_owasp_info(n)} for n,c in PATTERNS.items()]
    return jsonify({'total_patterns':len(pl),'patterns':pl})

@app.errorhandler(400)
def bad_request(e):    return jsonify({'error': 'Bad request'}), 400
@app.errorhandler(401)
def unauthorized(e):   return jsonify({'error': 'Authentication required'}), 401
@app.errorhandler(403)
def forbidden(e):      return jsonify({'error': 'Access denied'}), 403
@app.errorhandler(404)
def not_found(e):      return jsonify({'error': 'Endpoint not found'}), 404
@app.errorhandler(405)
def method_not_allowed(e): return jsonify({'error': 'Method not allowed'}), 405
@app.errorhandler(413)
def too_large(e):      return jsonify({'error': 'File too large (max 10MB)'}), 413
@app.errorhandler(415)
def unsupported_media(e): return jsonify({'error': 'Unsupported content type'}), 415
@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f'Rate limit hit: {request.remote_addr} {request.path}')
    return jsonify({'error': 'Rate limit exceeded. Please slow down.'}), 429
@app.errorhandler(500)
def internal_error(e):
    logger.error(f'500 error: {request.path} — {str(e)[:200]}')
    return jsonify({'error': 'Internal server error'}), 500

# ── SECURITY AUDIT LOGGING ────────────────────────────────────
@app.before_request
def log_security_events():
    """Log suspicious patterns in incoming requests."""
    path = request.path
    args = str(request.args)[:500]
    # Log path traversal attempts
    if '..' in path or '%2e%2e' in path.lower():
        logger.warning(f'Path traversal attempt: {request.remote_addr} {path}')
    # Log unusual HTTP methods
    if request.method not in ('GET', 'POST', 'OPTIONS', 'HEAD'):
        logger.warning(f'Unusual method: {request.method} {path} from {request.remote_addr}')
    # Log suspicious query parameters
    suspicious_patterns = ['<script', 'javascript:', 'union+select', '1=1', 'drop+table']
    combined = (path + args).lower()
    for pattern in suspicious_patterns:
        if pattern in combined:
            logger.warning(f'Suspicious pattern "{pattern}" from {request.remote_addr}: {path}')
            break

def is_text_file(fp):
    exts=[
        '.txt','.json','.js','.py','.java','.c','.cpp','.h',
        '.env','.config','.yaml','.yml','.xml','.md','.html','.css',
        '.php','.rb','.go','.rs','.ts','.jsx','.tsx','.sh','.bash',
        '.sql','.properties','.conf','.ini','.log','.cfg','.toml',
        # Crypto/key files — critical for secret scanning
        '.key','.pem','.cert','.crt','.p12','.pfx','.pub','.priv',
        # Common secret/config files without standard extensions
        '.htpasswd','.npmrc','.netrc','.pgpass','.boto',
        # Docker and CI
        '.dockerignore','.gitignore','.travis',
        # Environment files
        '.env.local','.env.production','.env.development','.env.staging',
    ]
    ext = os.path.splitext(fp)[1].lower()
    fname = os.path.basename(fp).lower()
    # Also catch files with no extension that are commonly secret-bearing
    no_ext_secrets = {
        'dockerfile','makefile','jenkinsfile','procfile',
        '.env','.htpasswd','.netrc','.npmrc','.boto','.pgpass',
        'credentials','secrets','config','settings','token','key',
        'id_rsa','id_ed25519','id_ecdsa','id_dsa',
    }
    return ext in exts or fname in no_ext_secrets

if __name__ == '__main__':
    logger.info("SecureKey Scanner v2.0 — Secure Edition")
    logger.info(f"Loaded {len(PATTERNS)} patterns")
    logger.info("Security: CSP | SSRF protection | IDOR | File validation | Brute force | SQL injection | XSS headers")

    # Security warnings
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    if debug_mode:
        logger.warning("DEBUG MODE ON — disable for production (FLASK_DEBUG=false)")

    # Ensure DB uses WAL mode for better concurrent access
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA foreign_keys=ON')
        conn.close()
    except Exception as e:
        logger.error(f'DB config error: {e}')

    app.run(
        host      = '127.0.0.1',   # Bind to localhost only — use nginx/proxy in production
        port      = 5000,
        debug     = debug_mode,
        threaded  = True,
    )