"""
Scholar Tracker — Production-hardened Flask application.

Security layers applied (cumulative across v3→v5):

AUTH (v3)
  scrypt password hashing · session expiry (2h + 30min idle) · secure/httponly/samesite
  cookies · session fixation prevention · IP rate limiting · account lockout (10 fails/15min)
  email verification · password reset (HMAC token, 1h, single-use) · password strength
  enforcement · constant-time login · demo creds removed · logout via POST · CSRF on all
  state-changing forms · forced first-login password change · auth audit log

IDOR (v4)
  assert_submission_access() centralises ownership enforcement for all file/submission routes ·
  Admin role explicit read-only with audit trail · assign-guide validates roles ·
  delete-user self-deletion guard · upload validates guide role · toggle_milestone 403 +
  audit on failure · review status whitelist · field length caps

DEPLOYMENT / INPUT / ABUSE (v5)
  A1  — max-length caps on every form field and query param
  A2  — due_date validated as ISO 8601 date before DB insert
  A3  — upload_mode whitelisted to {'zip','files'}
  A4  — repository search query capped at 200 chars
  A5  — |safe removed from flash messages (XSS)
  A6  — submission_detail.html: filename via textContent not innerHTML (XSS)
  A7  — upload.html: file.name HTML-escaped before innerHTML insertion (XSS)
  A8  — HTTPS redirect enforced in production (HTTPS=true env)
  A9  — Full security header suite (CSP, HSTS, X-Frame, X-Content-Type, Referrer, Permissions)
  A10 — Structured JSON logging to rotating file + console; request/error/auth event logging
  A11 — Generic @rate_limit() decorator; applied to register, forgot-password,
         resend-verification, upload, repository
  A12 — SMTP STARTTLS verified; MAIL_USE_SSL env var for port-465 SSL mode
  A13 — Startup guard: production mode refuses to start without SECRET_KEY env var
  A14 — Zip-bomb protection: MAX_EXTRACTED_BYTES (500 MB) per project upload
  A15 — rel_paths[] for folder upload rejects any path containing '..' segments
"""

import os, sqlite3, secrets, zipfile, mimetypes, hashlib, hmac, time, re, logging
from datetime import datetime, date, timedelta
from functools import wraps
from logging.handlers import RotatingFileHandler
from flask import (Flask, render_template, redirect, url_for, request,
                   flash, session, send_from_directory, g, abort,
                   Response, jsonify)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ═══════════════════════════════════════════════════════════════════════════════
#  A10 — STRUCTURED LOGGING
#  Configured before Flask app creation so every component can use it.
# ═══════════════════════════════════════════════════════════════════════════════

class _JsonFormatter(logging.Formatter):
    """Emit one JSON object per line — easy to pipe into any log aggregator."""
    def format(self, record):
        import json
        data = {
            'ts':      self.formatTime(record, '%Y-%m-%dT%H:%M:%S'),
            'level':   record.levelname,
            'logger':  record.name,
            'msg':     record.getMessage(),
        }
        if record.exc_info:
            data['exc'] = self.formatException(record.exc_info)
        return json.dumps(data)

def _configure_logging(log_dir: str) -> logging.Logger:
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger('scholar')
    logger.setLevel(logging.DEBUG)
    if logger.handlers:
        return logger  # already configured (e.g. reloader)

    fmt = _JsonFormatter()

    # Rotating file handler — 10 MB per file, keep 5 backups
    fh = RotatingFileHandler(
        os.path.join(log_dir, 'scholar.log'),
        maxBytes=10 * 1024 * 1024, backupCount=5, encoding='utf-8')
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)

    # Console handler (info+ in prod, debug in dev)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

LOG_DIR = os.environ.get('LOG_DIR', os.path.join(os.path.dirname(__file__), 'logs'))
log = _configure_logging(LOG_DIR)

# ═══════════════════════════════════════════════════════════════════════════════
#  APP CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

app = Flask(__name__)

_IS_PRODUCTION = os.environ.get('FLASK_ENV', 'development').lower() == 'production'
_SECRET_KEY    = os.environ.get('SECRET_KEY')

# A13 — refuse to start in production without a real SECRET_KEY
if _IS_PRODUCTION and not _SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY environment variable must be set in production. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(64))\""
    )
if not _SECRET_KEY:
    import warnings
    warnings.warn(
        "SECRET_KEY not set — using ephemeral key. Sessions will not persist across restarts. "
        "Set SECRET_KEY env var before deploying.", stacklevel=2)
    _SECRET_KEY = secrets.token_hex(64)

app.config.update(
    SECRET_KEY                  = _SECRET_KEY,
    DATABASE                    = os.path.join(os.path.dirname(__file__), 'scholar_tracker.db'),
    UPLOAD_FOLDER               = os.path.join(os.path.dirname(__file__), 'uploads'),
    MAX_CONTENT_LENGTH          = 100 * 1024 * 1024,   # 100 MB upload ceiling

    # Session security
    SESSION_COOKIE_HTTPONLY     = True,
    SESSION_COOKIE_SAMESITE     = 'Lax',
    SESSION_COOKIE_SECURE       = _IS_PRODUCTION,       # only True in production
    PERMANENT_SESSION_LIFETIME  = timedelta(hours=2),
    SESSION_IDLE_TIMEOUT        = 1800,                 # 30 min idle
)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ── Constants ─────────────────────────────────────────────────────────────────
MAX_LOGIN_ATTEMPTS   = 10
LOCKOUT_SECONDS      = 900       # 15-min account lockout
RATE_WINDOW_SECONDS  = 60
RATE_MAX_PER_WINDOW  = 10        # per-IP ceiling per 60s
VERIFY_TOKEN_TTL     = 86400     # 24 h
RESET_TOKEN_TTL      = 3600      # 1 h
MIN_PASSWORD_LEN     = 8
MAX_EXTRACTED_BYTES  = 500 * 1024 * 1024   # A14 — zip bomb protection (500 MB)

# A1 — field length caps (applied at every form.get() call)
MAX_EMAIL    = 254
MAX_NAME     = 100
MAX_PASSWORD = 128
MAX_TITLE    = 200
MAX_DESC     = 1000
MAX_COMMIT   = 200
MAX_TASK     = 200
MAX_QUERY    = 200
MAX_FEEDBACK = 2000

# ═══════════════════════════════════════════════════════════════════════════════
#  FILE-TYPE HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

TEXT_EXTENSIONS = {
    'py','js','ts','jsx','tsx','html','htm','css','scss','sass','less',
    'java','c','cpp','cc','h','hpp','cs','go','rb','php','swift','kt',
    'rs','r','m','sh','bash','zsh','ps1','md','txt','rst','tex',
    'json','yaml','yml','toml','ini','cfg','conf','env','sql','xml',
    'svg','csv','tsv','log','lock','gitignore','dockerfile','makefile',
}
IMAGE_EXTENSIONS   = {'png','jpg','jpeg','gif','bmp','webp','ico'}
PDF_EXTENSIONS     = {'pdf'}
BLOCKED_EXTENSIONS = {'exe','msi','dll','com','scr','pif','vbs'}

def get_ext(fn):       return fn.rsplit('.', 1)[-1].lower() if '.' in fn else ''
def allowed_file(fn):  return get_ext(fn) not in BLOCKED_EXTENSIONS
def is_text_file(fn):  return get_ext(fn) in TEXT_EXTENSIONS
def is_image_file(fn): return get_ext(fn) in IMAGE_EXTENSIONS
def is_pdf_file(fn):   return get_ext(fn) in PDF_EXTENSIONS

def file_language(fn):
    m = {'py':'python','js':'javascript','ts':'typescript','jsx':'javascript',
         'tsx':'typescript','html':'html','htm':'html','css':'css','scss':'scss',
         'java':'java','c':'c','cpp':'cpp','cc':'cpp','h':'c','hpp':'cpp',
         'cs':'csharp','go':'go','rb':'ruby','php':'php','swift':'swift',
         'kt':'kotlin','rs':'rust','r':'r','sh':'bash','bash':'bash',
         'sql':'sql','xml':'xml','json':'json','yaml':'yaml','yml':'yaml',
         'toml':'toml','md':'markdown','dockerfile':'dockerfile','tex':'latex'}
    return m.get(get_ext(fn), 'plaintext')

def fmt_size(b):
    for u in ('B','KB','MB','GB'):
        if b < 1024: return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} TB"

app.jinja_env.globals.update(
    is_text_file=is_text_file, is_image_file=is_image_file,
    is_pdf_file=is_pdf_file, file_language=file_language, fmt_size=fmt_size,
)

# ═══════════════════════════════════════════════════════════════════════════════
#  DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

@app.template_filter('dateformat')
def dateformat(value, fmt='%d %b %Y'):
    if not value: return ''
    if isinstance(value, (datetime, date)): return value.strftime(fmt)
    for pattern in ('%Y-%m-%d %H:%M:%S','%Y-%m-%d %H:%M','%Y-%m-%d'):
        try: return datetime.strptime(str(value), pattern).strftime(fmt)
        except ValueError: continue
    return str(value)

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

def qone(row): return dict(row) if row else None
def qall(rows): return [dict(r) for r in rows]

def init_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    NOT NULL,
            email           TEXT    UNIQUE NOT NULL,
            password_hash   TEXT    NOT NULL,
            role            TEXT    NOT NULL,
            guide_id        INTEGER,
            approved        INTEGER DEFAULT 1,
            email_verified  INTEGER DEFAULT 0,
            must_change_pw  INTEGER DEFAULT 0,
            created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        );
        CREATE TABLE IF NOT EXISTS auth_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            token_hash  TEXT    NOT NULL UNIQUE,
            purpose     TEXT    NOT NULL,
            expires_at  INTEGER NOT NULL,
            used        INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier   TEXT    NOT NULL,
            attempted_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS auth_audit (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event   TEXT    NOT NULL,
            ip      TEXT,
            detail  TEXT,
            ts      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        );
        CREATE TABLE IF NOT EXISTS submissions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id      INTEGER NOT NULL,
            guide_id        INTEGER NOT NULL,
            project_title   TEXT    NOT NULL,
            version_number  INTEGER DEFAULT 1,
            upload_date     TEXT    NOT NULL,
            teacher_feedback TEXT,
            status          TEXT    DEFAULT 'Pending',
            description     TEXT,
            commit_message  TEXT,
            storage_path    TEXT    NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS project_files (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            submission_id INTEGER NOT NULL,
            file_path     TEXT    NOT NULL,
            file_size     INTEGER DEFAULT 0,
            FOREIGN KEY(submission_id) REFERENCES submissions(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS milestones (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            task_name   TEXT    NOT NULL,
            due_date    TEXT    NOT NULL,
            student_id  INTEGER,
            completed   INTEGER DEFAULT 0
        );
    """)
    for sql in [
        "ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN must_change_pw  INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
        "ALTER TABLE submissions ADD COLUMN commit_message TEXT",
        "ALTER TABLE submissions ADD COLUMN storage_path TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE users ADD COLUMN approved INTEGER DEFAULT 1",
    ]:
        try: db.execute(sql); db.commit()
        except Exception: pass
    db.commit(); db.close()

def seed_admin():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    if not db.execute("SELECT id FROM users WHERE role='Admin'").fetchone():
        pw = secrets.token_urlsafe(16)
        db.execute(
            "INSERT INTO users(name,email,password_hash,role,approved,email_verified,must_change_pw)"
            " VALUES(?,?,?,?,1,1,1)",
            ('HOD / Admin','admin@scholar.edu',generate_password_hash(pw),'Admin'))
        db.commit()
        log.warning("ADMIN_SEEDED email=admin@scholar.edu — change password immediately")
        print("="*60)
        print(f"  Admin login : admin@scholar.edu")
        print(f"  Temp password: {pw}")
        print("  Change on first login.")
        print("="*60)
    db.close()

# ═══════════════════════════════════════════════════════════════════════════════
#  A10 — REQUEST / ERROR LOGGING HOOKS
# ═══════════════════════════════════════════════════════════════════════════════

@app.before_request
def _log_request():
    request._start_time = time.monotonic()

@app.after_request
def _log_response(response):
    duration_ms = round((time.monotonic() - getattr(request, '_start_time', time.monotonic())) * 1000)
    uid  = session.get('user_id', '-')
    # Log 4xx/5xx and slow requests (>1s) at WARNING; others at DEBUG
    level = logging.WARNING if (response.status_code >= 400 or duration_ms > 1000) else logging.DEBUG
    log.log(level, "HTTP",
            extra={'data': {
                'method': request.method,
                'path':   request.path,
                'status': response.status_code,
                'ms':     duration_ms,
                'ip':     get_ip(),
                'uid':    uid,
            }})
    return response

@app.errorhandler(403)
def err_403(e):
    log.warning("HTTP_403 path=%s ip=%s uid=%s", request.path, get_ip(), session.get('user_id','-'))
    return render_template('error.html', code=403, msg="Access denied."), 403

@app.errorhandler(404)
def err_404(e):
    # Log many 404s from same IP — could indicate scanning
    log.info("HTTP_404 path=%s ip=%s", request.path, get_ip())
    return render_template('error.html', code=404, msg="Page not found."), 404

@app.errorhandler(429)
def err_429(e):
    return render_template('error.html', code=429, msg="Too many requests. Please wait."), 429

@app.errorhandler(500)
def err_500(e):
    log.error("HTTP_500 path=%s ip=%s error=%s", request.path, get_ip(), str(e), exc_info=True)
    return render_template('error.html', code=500, msg="An internal error occurred."), 500

# ═══════════════════════════════════════════════════════════════════════════════
#  A8 + A9 — HTTPS REDIRECT & SECURITY HEADERS
# ═══════════════════════════════════════════════════════════════════════════════

@app.before_request
def enforce_https():
    """A8 — In production, redirect all plain HTTP to HTTPS."""
    if _IS_PRODUCTION and not request.is_secure and request.url.startswith('http://'):
        url = request.url.replace('http://', 'https://', 1)
        log.info("HTTPS_REDIRECT to=%s", url)
        return redirect(url, code=301)

@app.after_request
def add_security_headers(response):
    """A9 — Inject the full security header suite on every response."""
    # HSTS — tell browsers to always use HTTPS for 1 year (production only)
    if _IS_PRODUCTION:
        response.headers['Strict-Transport-Security'] = (
            'max-age=31536000; includeSubDomains; preload')

    # Prevent framing (clickjacking)
    response.headers['X-Frame-Options'] = 'DENY'

    # Prevent MIME-type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Minimal referrer leakage
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Disable browser features not needed
    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=(), payment=()')

    # Content Security Policy
    # — default-src: no inline scripts/styles except Bootstrap CDN and highlight.js
    # — script-src: CDN only; no unsafe-inline, no unsafe-eval
    # — style-src: CDN + inline styles (Bootstrap needs this)
    # — img-src: data: URIs (for blob: image viewer) + same origin
    # — frame-src: self (for PDF viewer iframe)
    # — object-src: none (no plugins)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data: blob:; "
        "frame-src 'self' blob:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )

    # Remove server fingerprinting header
    response.headers.pop('Server', None)

    return response

# ═══════════════════════════════════════════════════════════════════════════════
#  SECURITY HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def get_ip():
    return (request.headers.get('X-Forwarded-For') or
            request.remote_addr or 'unknown').split(',')[0].strip()

def audit(event, user_id=None, detail=None):
    try:
        db = get_db()
        db.execute("INSERT INTO auth_audit(user_id,event,ip,detail) VALUES(?,?,?,?)",
                   (user_id, event, get_ip(), detail))
        db.commit()
        log.info("AUDIT event=%s uid=%s ip=%s detail=%s", event, user_id, get_ip(), detail)
    except Exception as exc:
        log.error("AUDIT_WRITE_FAILED event=%s error=%s", event, exc)

# ── A11 — Generic rate limiting decorator ─────────────────────────────────────

def _purge_old_attempts(db, identifier, window):
    db.execute("DELETE FROM login_attempts WHERE identifier=? AND attempted_at<?",
               (identifier, int(time.time()) - window))

def _get_attempt_count(identifier, window=RATE_WINDOW_SECONDS):
    db = get_db()
    _purge_old_attempts(db, identifier, window)
    return db.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE identifier=? AND attempted_at>?",
        (identifier, int(time.time()) - window)).fetchone()[0]

def _record_attempt(identifier):
    db = get_db()
    db.execute("INSERT INTO login_attempts(identifier,attempted_at) VALUES(?,?)",
               (identifier, int(time.time())))
    db.commit()

def is_rate_limited(identifier, max_count=RATE_MAX_PER_WINDOW, window=RATE_WINDOW_SECONDS):
    return _get_attempt_count(identifier, window) >= max_count

def record_attempt(identifier):
    _record_attempt(identifier)

def rate_limit(max_per_window=RATE_MAX_PER_WINDOW, window=RATE_WINDOW_SECONDS,
               key_fn=None, scope='endpoint'):
    """
    A11 — Generic rate-limit decorator.
    key_fn(request) -> str: custom key builder.  Default: IP + endpoint.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip  = get_ip()
            key = key_fn(request) if key_fn else f"{ip}:{scope}:{f.__name__}"
            if is_rate_limited(key, max_per_window, window):
                audit('rate_limited', user_id=session.get('user_id'),
                      detail=f"key={key} endpoint={f.__name__}")
                log.warning("RATE_LIMITED key=%s endpoint=%s", key, f.__name__)
                abort(429)
            _record_attempt(key)
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ── Account lockout ───────────────────────────────────────────────────────────

def is_account_locked(email):
    db     = get_db()
    cutoff = int(time.time()) - LOCKOUT_SECONDS
    count  = db.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE identifier=? AND attempted_at>?",
        ('acct:' + email, cutoff)).fetchone()[0]
    if count >= MAX_LOGIN_ATTEMPTS:
        oldest = db.execute(
            "SELECT MIN(attempted_at) FROM login_attempts WHERE identifier=? AND attempted_at>?",
            ('acct:' + email, cutoff)).fetchone()[0] or int(time.time())
        remaining = max(0, (oldest + LOCKOUT_SECONDS) - int(time.time()))
        return True, remaining
    return False, 0

def record_failed_login(email):
    db = get_db()
    db.execute("INSERT INTO login_attempts(identifier,attempted_at) VALUES(?,?)",
               ('acct:' + email, int(time.time())))
    db.commit()

def clear_failed_logins(email):
    db = get_db()
    db.execute("DELETE FROM login_attempts WHERE identifier=?", ('acct:' + email,))
    db.commit()

# ── CSRF ──────────────────────────────────────────────────────────────────────

def generate_csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_hex(32)
    return session['_csrf']

def validate_csrf():
    token    = request.form.get('_csrf_token', '')
    expected = session.get('_csrf', '')
    if not expected or not hmac.compare_digest(token, expected):
        audit('csrf_failure', user_id=session.get('user_id'))
        abort(403)

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# ── Password strength ─────────────────────────────────────────────────────────

def check_password_strength(pw):
    if len(pw) < MIN_PASSWORD_LEN:
        return False, f'Password must be at least {MIN_PASSWORD_LEN} characters.'
    if not re.search(r'[A-Za-z]', pw):
        return False, 'Password must contain at least one letter.'
    if not re.search(r'\d', pw):
        return False, 'Password must contain at least one number.'
    return True, ''

# ── A1/A2 — Input sanitisation helpers ───────────────────────────────────────

def clean(value, max_len, default=''):
    """Strip, truncate, and return a string field."""
    return (value or default).strip()[:max_len]

def validate_date(value):
    """A2 — Return (ok, date_str). Accepts YYYY-MM-DD only."""
    v = clean(value, 10)
    try:
        datetime.strptime(v, '%Y-%m-%d')
        return True, v
    except ValueError:
        return False, ''

def validate_email(value):
    """Return cleaned email if valid RFC-5321-ish format, else None."""
    v = clean(value, MAX_EMAIL).lower()
    if re.match(r'^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{1,63}$', v):
        return v
    return None

# ── Token helpers ─────────────────────────────────────────────────────────────

def _token_hash(raw):
    return hashlib.sha256(raw.encode()).hexdigest()

def create_auth_token(user_id, purpose, ttl):
    raw    = secrets.token_urlsafe(32)
    h      = _token_hash(raw)
    expiry = int(time.time()) + ttl
    db     = get_db()
    db.execute("DELETE FROM auth_tokens WHERE user_id=? AND purpose=? AND used=0",
               (user_id, purpose))
    db.execute("INSERT INTO auth_tokens(user_id,token_hash,purpose,expires_at) VALUES(?,?,?,?)",
               (user_id, h, purpose, expiry))
    db.commit()
    return raw

def consume_auth_token(raw, purpose):
    h   = _token_hash(raw)
    db  = get_db()
    row = qone(db.execute(
        "SELECT * FROM auth_tokens WHERE token_hash=? AND purpose=? AND used=0",
        (h, purpose)).fetchone())
    if not row: return None
    if int(time.time()) > row['expires_at']:
        db.execute("DELETE FROM auth_tokens WHERE id=?", (row['id'],)); db.commit()
        return None
    db.execute("UPDATE auth_tokens SET used=1 WHERE id=?", (row['id'],)); db.commit()
    return row['user_id']

# ── A12 — Email (STARTTLS verified) ──────────────────────────────────────────

def send_email(to_address, subject, body_text):
    """
    Production: set MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD, MAIL_FROM.
    Set MAIL_USE_SSL=true for port-465 SSL connections.
    Development: prints link to console.
    """
    mail_server = os.environ.get('MAIL_SERVER')
    if mail_server:
        import smtplib
        from email.mime.text import MIMEText
        msg           = MIMEText(body_text)
        msg['Subject'] = subject
        msg['From']    = os.environ.get('MAIL_FROM', 'noreply@scholar.edu')
        msg['To']      = to_address
        use_ssl        = os.environ.get('MAIL_USE_SSL','false').lower() == 'true'
        port           = int(os.environ.get('MAIL_PORT', 465 if use_ssl else 587))
        try:
            if use_ssl:
                with smtplib.SMTP_SSL(mail_server, port) as s:
                    s.login(os.environ.get('MAIL_USERNAME',''),
                            os.environ.get('MAIL_PASSWORD',''))
                    s.send_message(msg)
            else:
                with smtplib.SMTP(mail_server, port) as s:
                    resp = s.starttls()
                    # A12 — verify STARTTLS actually succeeded (220 or 250)
                    if resp[0] not in (220, 250):
                        raise RuntimeError(f"STARTTLS failed: {resp}")
                    s.login(os.environ.get('MAIL_USERNAME',''),
                            os.environ.get('MAIL_PASSWORD',''))
                    s.send_message(msg)
            log.info("EMAIL_SENT to=%s subject=%s", to_address, subject)
        except Exception as e:
            log.error("EMAIL_FAILED to=%s error=%s", to_address, e, exc_info=True)
    else:
        log.info("EMAIL_DEV to=%s subject=%s", to_address, subject)
        print(f"\n{'='*60}\n  TO: {to_address}\n  SUBJECT: {subject}\n\n{body_text}\n{'='*60}\n")

def send_verification_email(user):
    raw  = create_auth_token(user['id'], 'verify_email', VERIFY_TOKEN_TTL)
    link = url_for('verify_email', token=raw, _external=True)
    send_email(user['email'], 'Scholar Tracker — Verify your email',
               f"Hi {user['name']},\n\nVerify your email (valid 24h):\n\n  {link}\n\n"
               f"If you did not register, ignore this email.\n")

def send_reset_email(user):
    raw  = create_auth_token(user['id'], 'reset_password', RESET_TOKEN_TTL)
    link = url_for('reset_password', token=raw, _external=True)
    send_email(user['email'], 'Scholar Tracker — Password reset',
               f"Hi {user['name']},\n\nReset your password (valid 1h):\n\n  {link}\n\n"
               f"If you did not request this, ignore this email.\n")

# ── Session timeout ───────────────────────────────────────────────────────────

@app.before_request
def enforce_session_timeout():
    if 'user_id' not in session: return
    now = int(time.time())
    if now - session.get('_last_active', 0) > app.config['SESSION_IDLE_TIMEOUT']:
        session.clear()
        flash('Session expired due to inactivity.', 'warning')
        return redirect(url_for('login'))
    session['_last_active'] = now

# ═══════════════════════════════════════════════════════════════════════════════
#  AUTH DECORATORS
# ═══════════════════════════════════════════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def d(*a, **k):
        if 'user_id' not in session:
            flash('Please log in.', 'warning')
            return redirect(url_for('login'))
        if session.get('must_change_pw') and request.endpoint not in ('change_password','logout'):
            flash('You must set a new password before continuing.', 'warning')
            return redirect(url_for('change_password'))
        return f(*a, **k)
    return d

def role_required(*roles):
    def dec(f):
        @wraps(f)
        def d(*a, **k):
            if session.get('role') not in roles:
                audit('access_denied', user_id=session.get('user_id'),
                      detail=f"endpoint={request.endpoint} required={roles}")
                flash('Access denied.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*a, **k)
        return d
    return dec

# ═══════════════════════════════════════════════════════════════════════════════
#  AUTH ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        validate_csrf()
        ip    = get_ip()
        # A1 — length caps on all auth inputs
        email = clean(request.form.get('email',''), MAX_EMAIL).lower()
        pw    = request.form.get('password','')[:MAX_PASSWORD]

        if is_rate_limited(ip):
            audit('rate_limited', detail=f"ip={ip}")
            flash('Too many login attempts. Please wait.', 'danger')
            return render_template('login.html'), 429
        record_attempt(ip)

        locked, remaining = is_account_locked(email)
        if locked:
            flash(f'Account locked. Try again in {(remaining//60)+1} minute(s).', 'danger')
            return render_template('login.html'), 429

        db   = get_db()
        user = qone(db.execute("SELECT * FROM users WHERE LOWER(email)=?", (email,)).fetchone())
        _dummy = 'scrypt:32768:8:1$dummy$' + 'a' * 43
        pw_ok  = check_password_hash(user['password_hash'] if user else _dummy, pw)

        if not user or not pw_ok:
            record_failed_login(email)
            audit('login_failed', detail=f"email={email}")
            flash('Invalid email or password.', 'danger')
            return render_template('login.html')

        if not user.get('approved', 1):
            audit('login_blocked_unapproved', user_id=user['id'])
            flash('Account pending approval.', 'warning')
            return render_template('login.html')

        if not user.get('email_verified', 0):
            audit('login_blocked_unverified', user_id=user['id'])
            flash('Please verify your email. '
                  '<a href="/resend-verification" class="alert-link">Resend link</a>.', 'warning')
            return render_template('login.html')

        clear_failed_logins(email)
        audit('login_success', user_id=user['id'])
        session.clear()
        session.permanent = True
        session.update(user_id=user['id'], user_name=user['name'], role=user['role'],
                       must_change_pw=bool(user.get('must_change_pw', 0)),
                       _last_active=int(time.time()))
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    validate_csrf()
    audit('logout', user_id=session.get('user_id'))
    session.clear()
    flash('You have been signed out.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
@rate_limit(max_per_window=5, window=300, scope='register')   # A11 — 5 registrations / 5 min / IP
def register():
    db     = get_db()
    guides = qall(db.execute("SELECT id,name FROM users WHERE role='Guide' ORDER BY name").fetchall())
    if request.method == 'POST':
        validate_csrf()
        name     = clean(request.form.get('name',''),     MAX_NAME)
        email    = validate_email(request.form.get('email',''))
        pw       = request.form.get('password','')[:MAX_PASSWORD]
        guide_id = clean(request.form.get('guide_id',''), 20) or None

        if not name or not email or not pw:
            flash('All fields are required.', 'danger')
            return render_template('register.html', guides=guides)
        if not email:
            flash('Invalid email address.', 'danger')
            return render_template('register.html', guides=guides)

        pw_ok, pw_msg = check_password_strength(pw)
        if not pw_ok:
            flash(pw_msg, 'danger')
            return render_template('register.html', guides=guides)

        if guide_id:
            if not db.execute("SELECT id FROM users WHERE id=? AND role='Guide'",
                              (guide_id,)).fetchone():
                flash('Invalid guide selected.', 'danger')
                return render_template('register.html', guides=guides)

        if db.execute("SELECT id FROM users WHERE LOWER(email)=?", (email,)).fetchone():
            flash("If this email isn't already registered, your account has been created. "
                  "Check your inbox.", 'info')
            return redirect(url_for('login'))

        db.execute(
            "INSERT INTO users(name,email,password_hash,role,guide_id,approved,email_verified)"
            " VALUES(?,?,?,?,?,1,0)",
            (name, email, generate_password_hash(pw),
             'Student', int(guide_id) if guide_id else None))
        db.commit()
        user = qone(db.execute("SELECT * FROM users WHERE LOWER(email)=?", (email,)).fetchone())
        audit('registered', user_id=user['id'])
        send_verification_email(user)
        flash('Account created! Check your email for a verification link.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', guides=guides)

@app.route('/verify-email/<token>')
def verify_email(token):
    user_id = consume_auth_token(token, 'verify_email')
    if not user_id:
        flash('Verification link invalid or expired.', 'danger')
        return redirect(url_for('login'))
    db = get_db()
    db.execute("UPDATE users SET email_verified=1 WHERE id=?", (user_id,))
    db.commit()
    audit('email_verified', user_id=user_id)
    flash('Email verified! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/resend-verification', methods=['GET','POST'])
@rate_limit(max_per_window=3, window=300, scope='resend_verify')  # A11 — 3/5min/IP
def resend_verification():
    if request.method == 'POST':
        validate_csrf()
        email = validate_email(request.form.get('email',''))
        if email:
            db   = get_db()
            user = qone(db.execute(
                "SELECT * FROM users WHERE LOWER(email)=? AND email_verified=0", (email,)).fetchone())
            if user:
                send_verification_email(user)
                audit('resend_verification', user_id=user['id'])
        flash("If that email is registered and unverified, a new link has been sent.", 'info')
        return redirect(url_for('login'))
    return render_template('resend_verification.html')

@app.route('/forgot-password', methods=['GET','POST'])
@rate_limit(max_per_window=3, window=300, scope='forgot_pw')  # A11 — 3/5min/IP
def forgot_password():
    if request.method == 'POST':
        validate_csrf()
        email = validate_email(request.form.get('email',''))
        if email:
            db   = get_db()
            user = qone(db.execute(
                "SELECT * FROM users WHERE LOWER(email)=? AND email_verified=1", (email,)).fetchone())
            if user:
                send_reset_email(user)
                audit('password_reset_requested', user_id=user['id'])
        flash("If that email belongs to a verified account, a reset link has been sent.", 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET','POST'])
def reset_password(token):
    h   = _token_hash(token)
    db  = get_db()
    row = qone(db.execute(
        "SELECT * FROM auth_tokens WHERE token_hash=? AND purpose='reset_password' AND used=0",
        (h,)).fetchone())
    if not row or int(time.time()) > row['expires_at']:
        flash('Reset link invalid or expired.', 'danger')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        validate_csrf()
        pw  = request.form.get('password','')[:MAX_PASSWORD]
        pw2 = request.form.get('password2','')[:MAX_PASSWORD]
        if pw != pw2:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)
        pw_ok, pw_msg = check_password_strength(pw)
        if not pw_ok:
            flash(pw_msg, 'danger')
            return render_template('reset_password.html', token=token)
        user_id = consume_auth_token(token, 'reset_password')
        if not user_id:
            flash('Reset link already used or expired.', 'danger')
            return redirect(url_for('forgot_password'))
        db.execute("UPDATE users SET password_hash=?, must_change_pw=0 WHERE id=?",
                   (generate_password_hash(pw), user_id))
        row = qone(db.execute("SELECT email FROM users WHERE id=?", (user_id,)).fetchone())
        if row: clear_failed_logins(row['email'])
        db.commit()
        audit('password_reset_complete', user_id=user_id)
        flash('Password updated. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route('/change-password', methods=['GET','POST'])
@login_required
def change_password():
    if request.method == 'POST':
        validate_csrf()
        current = request.form.get('current_password','')[:MAX_PASSWORD]
        pw      = request.form.get('password','')[:MAX_PASSWORD]
        pw2     = request.form.get('password2','')[:MAX_PASSWORD]
        db      = get_db()
        user    = qone(db.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone())
        if not check_password_hash(user['password_hash'], current):
            audit('change_pw_wrong_current', user_id=user['id'])
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html')
        if pw != pw2:
            flash('New passwords do not match.', 'danger')
            return render_template('change_password.html')
        pw_ok, pw_msg = check_password_strength(pw)
        if not pw_ok:
            flash(pw_msg, 'danger')
            return render_template('change_password.html')
        db.execute("UPDATE users SET password_hash=?, must_change_pw=0 WHERE id=?",
                   (generate_password_hash(pw), user['id']))
        db.commit()
        session['must_change_pw'] = False
        audit('password_changed', user_id=user['id'])
        flash('Password changed.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('change_password.html')

# ═══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db(); role = session['role']
    if role == 'Admin':
        teachers  = qall(db.execute("SELECT * FROM users WHERE role='Guide' ORDER BY name").fetchall())
        students  = qall(db.execute(
            "SELECT u.*,g.name as guide_name FROM users u "
            "LEFT JOIN users g ON u.guide_id=g.id WHERE u.role='Student' ORDER BY u.name").fetchall())
        total_sub = db.execute("SELECT COUNT(*) FROM submissions").fetchone()[0]
        approved  = db.execute("SELECT COUNT(*) FROM submissions WHERE status='Approved'").fetchone()[0]
        pending   = db.execute("SELECT COUNT(*) FROM submissions WHERE status='Pending'").fetchone()[0]
        return render_template('admin_dashboard.html', teachers=teachers, students=students,
                               total_sub=total_sub, approved=approved, pending=pending)
    if role == 'Student':
        subs = qall(db.execute(
            "SELECT s.*,u.name as guide_name,"
            "(SELECT COUNT(*) FROM project_files WHERE submission_id=s.id) as file_count "
            "FROM submissions s JOIN users u ON s.guide_id=u.id "
            "WHERE s.student_id=? ORDER BY s.upload_date DESC", (session['user_id'],)).fetchall())
        ms = qall(db.execute("SELECT * FROM milestones WHERE student_id=? ORDER BY due_date",
                             (session['user_id'],)).fetchall())
        return render_template('student_dashboard.html', submissions=subs, milestones=ms,
                               today=date.today().isoformat())
    rows = qall(db.execute("SELECT * FROM users WHERE role='Student' AND guide_id=?",
                            (session['user_id'],)).fetchall())
    my_st = []
    for s in rows:
        s['sub_count'] = db.execute("SELECT COUNT(*) FROM submissions WHERE student_id=?",
                                     (s['id'],)).fetchone()[0]
        my_st.append(s)
    pending  = db.execute("SELECT COUNT(*) FROM submissions WHERE guide_id=? AND status='Pending'",
                          (session['user_id'],)).fetchone()[0]
    approved = db.execute("SELECT COUNT(*) FROM submissions WHERE guide_id=? AND status='Approved'",
                          (session['user_id'],)).fetchone()[0]
    nc       = db.execute("SELECT COUNT(*) FROM submissions WHERE guide_id=? AND status='Needs Changes'",
                          (session['user_id'],)).fetchone()[0]
    rec = qall(db.execute(
        "SELECT s.*,u.name as student_name,"
        "(SELECT COUNT(*) FROM project_files WHERE submission_id=s.id) as file_count "
        "FROM submissions s JOIN users u ON s.student_id=u.id "
        "WHERE s.guide_id=? ORDER BY s.upload_date DESC LIMIT 10", (session['user_id'],)).fetchall())
    return render_template('guide_dashboard.html', students=my_st, pending=pending,
                           approved=approved, needs_changes=nc, recent_submissions=rec)

# ═══════════════════════════════════════════════════════════════════════════════
#  ADMIN
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/admin/add-teacher', methods=['POST'])
@login_required
@role_required('Admin')
def admin_add_teacher():
    validate_csrf()
    db    = get_db()
    name  = clean(request.form.get('name',''),     MAX_NAME)
    email = validate_email(request.form.get('email',''))
    pw    = request.form.get('password','')[:MAX_PASSWORD]
    if not name or not email or not pw:
        flash('All fields required.', 'danger'); return redirect(url_for('dashboard'))
    pw_ok, pw_msg = check_password_strength(pw)
    if not pw_ok:
        flash(pw_msg, 'danger'); return redirect(url_for('dashboard'))
    if db.execute("SELECT id FROM users WHERE LOWER(email)=?", (email,)).fetchone():
        flash('Email already exists.', 'danger'); return redirect(url_for('dashboard'))
    db.execute(
        "INSERT INTO users(name,email,password_hash,role,approved,email_verified,must_change_pw)"
        " VALUES(?,?,?,?,1,1,1)",
        (name, email, generate_password_hash(pw), 'Guide'))
    db.commit()
    audit('admin_add_teacher', user_id=session['user_id'], detail=f"email={email}")
    flash(f'Teacher "{name}" added. They must change password on first login.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/delete-user/<int:uid>', methods=['POST'])
@login_required
@role_required('Admin')
def admin_delete_user(uid):
    validate_csrf()
    db = get_db()
    if uid == session['user_id']:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('dashboard'))
    user = qone(db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone())
    if not user:
        flash('User not found.', 'danger'); return redirect(url_for('dashboard'))
    if user['role'] == 'Admin':
        audit('admin_delete_blocked_admin', user_id=session['user_id'], detail=f"target_id={uid}")
        flash('Admin accounts cannot be deleted.', 'danger')
        return redirect(url_for('dashboard'))
    db.execute("DELETE FROM users WHERE id=?", (uid,)); db.commit()
    audit('admin_delete_user', user_id=session['user_id'],
          detail=f"deleted_id={uid} role={user['role']}")
    flash(f'User "{user["name"]}" removed.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/assign-guide', methods=['POST'])
@login_required
@role_required('Admin')
def admin_assign_guide():
    validate_csrf()
    db  = get_db()
    sid = clean(request.form.get('student_id',''), 20)
    gid = clean(request.form.get('guide_id',''),   20) or None
    if not sid:
        flash('Student is required.', 'danger'); return redirect(url_for('dashboard'))
    if not qone(db.execute("SELECT id FROM users WHERE id=? AND role='Student'",
                           (int(sid),)).fetchone()):
        audit('admin_assign_guide_invalid_student', user_id=session['user_id'],
              detail=f"bad_student_id={sid}")
        flash('Invalid student ID.', 'danger'); return redirect(url_for('dashboard'))
    if gid and not qone(db.execute("SELECT id FROM users WHERE id=? AND role='Guide'",
                                   (int(gid),)).fetchone()):
        audit('admin_assign_guide_invalid_guide', user_id=session['user_id'],
              detail=f"bad_guide_id={gid}")
        flash('Invalid guide ID.', 'danger'); return redirect(url_for('dashboard'))
    db.execute("UPDATE users SET guide_id=? WHERE id=?",
               (int(gid) if gid else None, int(sid)))
    db.commit()
    audit('admin_assign_guide', user_id=session['user_id'],
          detail=f"student_id={sid} guide_id={gid}")
    flash('Guide assigned.', 'success')
    return redirect(url_for('dashboard'))

# ═══════════════════════════════════════════════════════════════════════════════
#  PROJECT UPLOAD
# ═══════════════════════════════════════════════════════════════════════════════

def slugify(text):
    return re.sub(r'[\s_-]+','-', re.sub(r'[^\w\s-]','', text.lower().strip()))[:60]

def _safe_rel_path(rp):
    """
    A15 — Reject any path with '..' traversal components.
    Returns the cleaned relative path or None if unsafe.
    """
    rp = rp.replace('\\', '/').lstrip('/')
    parts = rp.split('/')
    # strip leading folder segment added by browser webkitRelativePath
    if len(parts) > 1:
        parts = parts[1:]
    if '..' in parts or '' in parts[:-1]:
        return None
    return '/'.join(parts)

def save_zip_project(zip_file, storage_path):
    """A14 — Abort if extracted bytes exceed MAX_EXTRACTED_BYTES (zip bomb protection)."""
    os.makedirs(storage_path, exist_ok=True)
    saved        = []
    total_bytes  = 0
    try:
        with zipfile.ZipFile(zip_file, 'r') as z:
            names  = [n for n in z.namelist() if not n.startswith('__MACOSX')]
            parts  = [n.split('/') for n in names if not n.endswith('/')]
            prefix = parts[0][0] if parts and all(p[0]==parts[0][0] for p in parts) else ''
            for name in names:
                if name.endswith('/') or '/.DS_Store' in name: continue
                rel = name[len(prefix)+1:] if prefix and name.startswith(prefix+'/') else name
                if not rel or not allowed_file(rel.split('/')[-1]): continue
                # A15 — reject path traversal inside zips
                if '..' in rel.split('/'): continue
                info = z.getinfo(name)
                total_bytes += info.file_size
                if total_bytes > MAX_EXTRACTED_BYTES:
                    log.warning("ZIP_BOMB_BLOCKED storage_path=%s total_bytes=%d", storage_path, total_bytes)
                    raise ValueError(f"Extraction limit exceeded ({fmt_size(MAX_EXTRACTED_BYTES)})")
                dest = os.path.join(storage_path, rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with z.open(name) as src, open(dest, 'wb') as dst:
                    dst.write(src.read())
                saved.append(rel)
    except zipfile.BadZipFile:
        pass
    return saved

def save_multifile_project(files, rel_paths, storage_path):
    os.makedirs(storage_path, exist_ok=True)
    saved = []
    for f, rp in zip(files, rel_paths):
        if not f or not f.filename: continue
        rel = _safe_rel_path(rp)      # A15
        if not rel or not allowed_file(rel.split('/')[-1]): continue
        dest = os.path.join(storage_path, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        f.save(dest); saved.append(rel)
    return saved

def collect_disk_files(storage_path):
    result = []
    for root, dirs, files in os.walk(storage_path):
        dirs[:] = sorted(d for d in dirs if not d.startswith('.'))
        for fn in sorted(files):
            if fn.startswith('.'): continue
            abs_p = os.path.join(root, fn)
            rel   = os.path.relpath(abs_p, storage_path).replace('\\','/')
            result.append((rel, os.path.getsize(abs_p)))
    return result

@app.route('/upload', methods=['GET','POST'])
@login_required
@role_required('Student')
@rate_limit(max_per_window=10, window=3600, scope='upload')   # A11 — 10 uploads/hr/IP
def upload():
    db      = get_db()
    guides  = qall(db.execute("SELECT id,name FROM users WHERE role='Guide' ORDER BY name").fetchall())
    student = qone(db.execute("SELECT guide_id FROM users WHERE id=?", (session['user_id'],)).fetchone())
    my_guide_id = student['guide_id'] if student else None

    if request.method == 'POST':
        validate_csrf()
        # A1 — all fields capped
        title = clean(request.form.get('project_title',''), MAX_TITLE)
        gid   = clean(request.form.get('guide_id',''),      20)
        desc  = clean(request.form.get('description',''),   MAX_DESC)
        msg   = clean(request.form.get('commit_message',''),MAX_COMMIT) or 'Initial upload'
        # A3 — upload_mode whitelisted
        mode  = request.form.get('upload_mode','zip')
        if mode not in ('zip', 'files'):
            mode = 'zip'

        if not title or not gid:
            flash('Title and teacher are required.', 'danger')
            return render_template('upload.html', guides=guides, my_guide_id=my_guide_id)

        if not qone(db.execute("SELECT id FROM users WHERE id=? AND role='Guide'",
                               (int(gid),)).fetchone()):
            audit('upload_invalid_guide', user_id=session['user_id'], detail=f"bad_guide_id={gid}")
            flash('Invalid teacher selected.', 'danger')
            return render_template('upload.html', guides=guides, my_guide_id=my_guide_id)

        ver  = db.execute("SELECT COUNT(*) FROM submissions WHERE student_id=? AND project_title=?",
                          (session['user_id'], title)).fetchone()[0] + 1
        slug = slugify(title)
        storage_path = os.path.join(app.config['UPLOAD_FOLDER'],
                                    str(session['user_id']), slug, f"v{ver}")
        saved = []
        try:
            if mode == 'zip':
                zf = request.files.get('zipfile')
                if not zf or not zf.filename.lower().endswith('.zip'):
                    flash('Please upload a .zip file.', 'danger')
                    return render_template('upload.html', guides=guides, my_guide_id=my_guide_id)
                saved = save_zip_project(zf, storage_path)
            else:
                files     = request.files.getlist('files[]')
                rel_paths = request.form.getlist('rel_paths[]')
                saved     = save_multifile_project(files, rel_paths, storage_path)
        except ValueError as e:
            flash(str(e), 'danger')
            return render_template('upload.html', guides=guides, my_guide_id=my_guide_id)

        if not saved:
            flash('No valid files were found in the upload.', 'danger')
            return render_template('upload.html', guides=guides, my_guide_id=my_guide_id)

        cur = db.execute(
            "INSERT INTO submissions(student_id,guide_id,project_title,version_number,"
            "upload_date,description,commit_message,status,storage_path) VALUES(?,?,?,?,?,?,?,'Pending',?)",
            (session['user_id'], int(gid), title, ver,
             datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), desc, msg, storage_path))
        sub_id = cur.lastrowid
        for rel, size in collect_disk_files(storage_path):
            db.execute("INSERT INTO project_files(submission_id,file_path,file_size) VALUES(?,?,?)",
                       (sub_id, rel, size))
        db.commit()
        log.info("UPLOAD sub_id=%d student=%d files=%d size=%s",
                 sub_id, session['user_id'], len(saved),
                 fmt_size(sum(s for _,s in collect_disk_files(storage_path))))
        flash(f'"{title}" v{ver} uploaded — {len(saved)} file(s)!', 'success')
        return redirect(url_for('submission_detail', sub_id=sub_id))

    return render_template('upload.html', guides=guides, my_guide_id=my_guide_id)

# ═══════════════════════════════════════════════════════════════════════════════
#  OWNERSHIP HELPER
# ═══════════════════════════════════════════════════════════════════════════════

def assert_submission_access(sub, require_write=False):
    role = session.get('role')
    uid  = session.get('user_id')
    if role == 'Student':
        if sub['student_id'] != uid:
            audit('idor_attempt', user_id=uid,
                  detail=f"student tried sub_id={sub['id']} student_id={sub['student_id']}")
            abort(403)
    elif role == 'Guide':
        if sub['guide_id'] != uid:
            audit('idor_attempt', user_id=uid,
                  detail=f"guide tried sub_id={sub['id']} guide_id={sub['guide_id']}")
            abort(403)
        if require_write and sub['guide_id'] != uid:
            abort(403)
    elif role == 'Admin':
        if require_write:
            audit('admin_write_attempt', user_id=uid, detail=f"sub_id={sub['id']}")
            abort(403)
        audit('admin_read_submission', user_id=uid, detail=f"sub_id={sub['id']}")
    else:
        abort(403)

# ═══════════════════════════════════════════════════════════════════════════════
#  FILE BROWSER
# ═══════════════════════════════════════════════════════════════════════════════

def build_tree(files):
    tree = {}
    for f in files:
        parts = f['file_path'].split('/')
        node  = tree
        for part in parts[:-1]:
            node = node.setdefault(part, {'__type':'dir','__children':{}})['__children']
        node[parts[-1]] = {'__type':'file','__meta':f}
    return tree

@app.route('/submission/<int:sub_id>')
@login_required
def submission_detail(sub_id):
    db        = get_db()
    sub_check = qone(db.execute(
        "SELECT id, student_id, guide_id FROM submissions WHERE id=?",
        (sub_id,)).fetchone())
    if not sub_check:
        flash('Not found.', 'danger'); return redirect(url_for('dashboard'))
    assert_submission_access(sub_check)
    sub = qone(db.execute(
        "SELECT s.*,st.name as student_name,st.email as student_email,g.name as guide_name "
        "FROM submissions s JOIN users st ON s.student_id=st.id "
        "JOIN users g ON s.guide_id=g.id WHERE s.id=?", (sub_id,)).fetchone())
    files    = qall(db.execute("SELECT * FROM project_files WHERE submission_id=? ORDER BY file_path",
                               (sub_id,)).fetchall())
    versions = qall(db.execute(
        "SELECT s.*, (SELECT COUNT(*) FROM project_files WHERE submission_id=s.id) as file_count "
        "FROM submissions s WHERE student_id=? AND project_title=? ORDER BY version_number",
        (sub['student_id'], sub['project_title'])).fetchall())
    tree       = build_tree(files)
    total_size = sum(f['file_size'] for f in files)
    return render_template('submission_detail.html', sub=sub, files=files,
                           versions=versions, tree=tree, total_size=total_size)

@app.route('/file/<int:sub_id>/<path:filepath>')
@login_required
def view_file(sub_id, filepath):
    db  = get_db()
    sub = qone(db.execute("SELECT * FROM submissions WHERE id=?", (sub_id,)).fetchone())
    if not sub: abort(404)
    assert_submission_access(sub)
    abs_path = os.path.join(sub['storage_path'], filepath)
    if not os.path.isfile(abs_path): abort(404)
    if not os.path.realpath(abs_path).startswith(os.path.realpath(sub['storage_path'])): abort(403)
    fname = os.path.basename(filepath)
    if is_text_file(fname):
        try:
            content = open(abs_path, encoding='utf-8', errors='replace').read()
            # A6 — filename returned in JSON; client must use textContent, not innerHTML
            return jsonify({'type':'text','content':content,
                            'language':file_language(fname),'name':fname})
        except Exception: abort(500)
    elif is_image_file(fname):
        mime = mimetypes.guess_type(fname)[0] or 'application/octet-stream'
        return send_from_directory(os.path.dirname(abs_path), fname, mimetype=mime)
    elif is_pdf_file(fname):
        return send_from_directory(os.path.dirname(abs_path), fname, mimetype='application/pdf')
    return jsonify({'type':'binary','name':fname,'size':fmt_size(os.path.getsize(abs_path))})

@app.route('/download-file/<int:sub_id>/<path:filepath>')
@login_required
def download_file(sub_id, filepath):
    db  = get_db()
    sub = qone(db.execute("SELECT * FROM submissions WHERE id=?", (sub_id,)).fetchone())
    if not sub: abort(404)
    assert_submission_access(sub)
    abs_path = os.path.join(sub['storage_path'], filepath)
    if not os.path.isfile(abs_path): abort(404)
    if not os.path.realpath(abs_path).startswith(os.path.realpath(sub['storage_path'])): abort(403)
    return send_from_directory(os.path.dirname(abs_path), os.path.basename(abs_path),
                               as_attachment=True)

@app.route('/download-project/<int:sub_id>')
@login_required
def download_project(sub_id):
    import io
    db  = get_db()
    sub = qone(db.execute("SELECT * FROM submissions WHERE id=?", (sub_id,)).fetchone())
    if not sub: abort(404)
    assert_submission_access(sub)
    buf  = io.BytesIO()
    slug = slugify(sub['project_title'])
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for rel, _ in collect_disk_files(sub['storage_path']):
            z.write(os.path.join(sub['storage_path'], rel),
                    arcname=f"{slug}_v{sub['version_number']}/{rel}")
    buf.seek(0)
    fname = f"{slug}_v{sub['version_number']}.zip"
    return Response(buf, mimetype='application/zip',
                    headers={'Content-Disposition': f'attachment; filename="{fname}"'})

# ═══════════════════════════════════════════════════════════════════════════════
#  REVIEW
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/review/<int:sub_id>', methods=['POST'])
@login_required
@role_required('Guide')
def review(sub_id):
    validate_csrf()
    db  = get_db()
    sub = qone(db.execute("SELECT * FROM submissions WHERE id=?", (sub_id,)).fetchone())
    if not sub or sub['guide_id'] != session['user_id']:
        audit('idor_review_attempt', user_id=session['user_id'], detail=f"sub_id={sub_id}")
        flash('Access denied.', 'danger'); return redirect(url_for('dashboard'))
    ALLOWED_STATUSES = {'Approved', 'Pending', 'Needs Changes'}
    status = request.form.get('status', 'Pending')
    if status not in ALLOWED_STATUSES:
        flash('Invalid status.', 'danger')
        return redirect(url_for('submission_detail', sub_id=sub_id))
    feedback = clean(request.form.get('feedback',''), MAX_FEEDBACK)
    db.execute("UPDATE submissions SET status=?,teacher_feedback=? WHERE id=?",
               (status, feedback, sub_id))
    db.commit()
    audit('review_submitted', user_id=session['user_id'],
          detail=f"sub_id={sub_id} status={status}")
    flash('Feedback submitted.', 'success')
    return redirect(url_for('submission_detail', sub_id=sub_id))

# ═══════════════════════════════════════════════════════════════════════════════
#  MILESTONES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/milestones', methods=['GET','POST'])
@login_required
@role_required('Guide')
def manage_milestones():
    db    = get_db()
    rows  = qall(db.execute("SELECT * FROM users WHERE role='Student' AND guide_id=?",
                             (session['user_id'],)).fetchall())
    my_st = []
    for s in rows:
        s['sub_count'] = db.execute("SELECT COUNT(*) FROM submissions WHERE student_id=?",
                                     (s['id'],)).fetchone()[0]
        my_st.append(s)
    if request.method == 'POST':
        validate_csrf()
        tn  = clean(request.form.get('task_name',''), MAX_TASK)
        sid = clean(request.form.get('student_id',''), 20) or None

        # A2 — validate due_date is a real ISO date
        date_ok, dd = validate_date(request.form.get('due_date',''))
        if not date_ok:
            flash('Invalid due date — use YYYY-MM-DD format.', 'danger')
            return redirect(url_for('manage_milestones'))
        if not tn:
            flash('Task name is required.', 'danger')
            return redirect(url_for('manage_milestones'))

        if sid:
            if not db.execute("SELECT id FROM users WHERE id=? AND guide_id=?",
                              (int(sid), session['user_id'])).fetchone():
                flash('Invalid student.', 'danger')
                return redirect(url_for('manage_milestones'))
        db.execute("INSERT INTO milestones(task_name,due_date,student_id) VALUES(?,?,?)",
                   (tn, dd, int(sid) if sid else None))
        db.commit()
        flash('Milestone added!', 'success')
        return redirect(url_for('manage_milestones'))
    ids = [s['id'] for s in my_st]; ms = []
    if ids:
        ph = ','.join('?'*len(ids))
        ms = qall(db.execute(
            f"SELECT m.*,u.name as student_name FROM milestones m "
            f"LEFT JOIN users u ON m.student_id=u.id "
            f"WHERE m.student_id IN ({ph}) ORDER BY m.due_date", ids).fetchall())
    return render_template('milestones.html', milestones=ms, students=my_st,
                           today=date.today().isoformat())

@app.route('/milestone/toggle/<int:m_id>', methods=['POST'])
@login_required
def toggle_milestone(m_id):
    validate_csrf()
    db = get_db()
    ms = qone(db.execute(
        "SELECT m.*,u.guide_id FROM milestones m "
        "LEFT JOIN users u ON m.student_id=u.id WHERE m.id=?", (m_id,)).fetchone())
    if not ms: abort(404)
    role = session['role']; uid = session['user_id']
    ok = ((role=='Student' and ms['student_id']==uid) or
          (role=='Guide'   and ms['guide_id']==uid) or role=='Admin')
    if not ok:
        audit('idor_milestone_toggle', user_id=uid,
              detail=f"m_id={m_id} student_id={ms['student_id']} guide_id={ms['guide_id']}")
        abort(403)
    db.execute("UPDATE milestones SET completed=? WHERE id=?",
               (0 if ms['completed'] else 1, m_id))
    db.commit()
    return redirect(request.referrer or url_for('dashboard'))

# ═══════════════════════════════════════════════════════════════════════════════
#  REPOSITORY
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/repository')
@login_required
@rate_limit(max_per_window=30, window=60, scope='repository')  # A11 — 30 searches/min/IP
def repository():
    db = get_db()
    # A4 — search query capped at 200 chars
    q = clean(request.args.get('q',''), MAX_QUERY)
    base = ("SELECT s.*,u.name as student_name,"
            "(SELECT COUNT(*) FROM project_files WHERE submission_id=s.id) as file_count "
            "FROM submissions s JOIN users u ON s.student_id=u.id WHERE s.status='Approved'")
    if q:
        res = qall(db.execute(base + " AND(s.project_title LIKE ? OR s.description LIKE ?) "
                              "ORDER BY s.upload_date DESC", (f'%{q}%', f'%{q}%')).fetchall())
    else:
        res = qall(db.execute(base + " ORDER BY s.upload_date DESC").fetchall())
    return render_template('repository.html', results=res, query=q)

@app.route('/students')
@login_required
@role_required('Guide')
def students():
    db   = get_db()
    rows = qall(db.execute("SELECT * FROM users WHERE role='Student' AND guide_id=?",
                            (session['user_id'],)).fetchall())
    data = []
    for s in rows:
        subs = qall(db.execute(
            "SELECT s.*,(SELECT COUNT(*) FROM project_files WHERE submission_id=s.id) as file_count "
            "FROM submissions s WHERE student_id=? ORDER BY upload_date DESC",
            (s['id'],)).fetchall())
        data.append({'user':s,'submissions':subs,'latest':subs[0] if subs else None})
    return render_template('students.html', student_data=data)

# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    init_db()
    seed_admin()
    debug = os.environ.get('FLASK_DEBUG','false').lower() == 'true'
    if debug and _IS_PRODUCTION:
        raise RuntimeError("FLASK_DEBUG must not be True in production (FLASK_ENV=production)")
    app.run(debug=debug, port=5000)
