""" 
Group Members :
Maryam Khan CR-22021
Ayesha Yousuf CR-22004

        FIXED VERSION 

All five vulnerabilities patched:
  1. SQL Injection      → parameterized queries (? placeholders)
  2. XSS               → Jinja2 auto-escaping (no |safe), input sanitization
  3. Broken Auth       → PBKDF2-SHA256 + random salt + rate limiting + strong secret
  4. Command Injection → shlex validation + no shell=True
  5. IDOR              → ownership + role check before returning user data
"""

from flask import Flask, request, jsonify, render_template_string, session
import sqlite3, hashlib, os, secrets, time, re, subprocess
from collections import defaultdict

app = Flask(__name__)
# FIX 3: Strong random secret — never hardcoded
app.secret_key = secrets.token_hex(32)

DB_PATH = "fixed.db"

# ─── Secure Password Helpers (FIX 3) ──────────────────────────────────────────
ITERATIONS = 260_000   # NIST-recommended for PBKDF2-SHA256 (2024)

def hash_password(password: str) -> str:
    """PBKDF2-SHA256 with a random 16-byte salt. Stores as 'salt_hex:dk_hex'."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return salt.hex() + ":" + dk.hex()

def verify_password(stored: str, candidate: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    try:
        salt_hex, dk_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        dk   = hashlib.pbkdf2_hmac("sha256", candidate.encode(), salt, ITERATIONS)
        return secrets.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False

# ─── Rate Limiting (FIX 3) ────────────────────────────────────────────────────
_attempts: dict = defaultdict(list)
MAX_ATTEMPTS, WINDOW = 5, 60   # 5 attempts per 60 seconds per IP

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    _attempts[ip] = [t for t in _attempts[ip] if now - t < WINDOW]
    if len(_attempts[ip]) >= MAX_ATTEMPTS:
        return True
    _attempts[ip].append(now)
    return False

# ─── Database Setup ────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE, password TEXT,
        role TEXT DEFAULT 'user', email TEXT, balance REAL DEFAULT 1000.0)""")
    c.execute("""CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT, author TEXT, content TEXT)""")
    for username, pwd, role, email, bal in [
        ("admin", "admin123", "admin", "admin@securebank.com", 99999.0),
        ("alice", "password", "user",  "alice@securebank.com", 5000.0),
        ("bob",   "bob123",   "user",  "bob@securebank.com",   2500.0),
    ]:
        try:
            c.execute("INSERT INTO users (username,password,role,email,balance) VALUES (?,?,?,?,?)",
                      (username, hash_password(pwd), role, email, bal))
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

# ─── Templates ────────────────────────────────────────────────────────────────
NAV = '<nav style="margin:10px 0"><a href="/">Home</a> | <a href="/comments">Comments</a> | <a href="/ping">Ping</a> | <a href="/user/1">Profile</a></nav>'
STYLE = '<style>body{font-family:Arial;max-width:860px;margin:30px auto;padding:20px;background:#f0fff4}.card{background:#fff;padding:20px;border-radius:8px;margin:15px 0;box-shadow:0 2px 6px rgba(0,0,0,.1)}input{padding:8px;margin:4px;border:1px solid #ddd;border-radius:4px}button{padding:9px 18px;background:#27ae60;color:#fff;border:none;border-radius:4px;cursor:pointer}.fb{background:#27ae60;color:#fff;font-size:11px;padding:2px 8px;border-radius:10px}pre{background:#111;color:#0f0;padding:12px;border-radius:4px}code{background:#e8f8f0;padding:2px 4px;border-radius:3px}h1{color:#27ae60}a{color:#27ae60}</style>'

HOME_HTML = f"""<!DOCTYPE html><html><head><title>SecureBank</title>{STYLE}</head><body>
<h1>&#128274; SecureBank <span class="fb">FIXED VERSION</span></h1>{NAV}<hr>
<div class="card">
  <h2>Login <span class="fb">FIX #1: Parameterized Query</span></h2>
  <form method="POST" action="/login">
    <input name="username" placeholder="Username"><br>
    <input name="password" type="password" placeholder="Password"><br><br>
    <button>Login</button>
  </form>
</div>
<div class="card">
  <h2>Register <span class="fb">FIX #3: PBKDF2-SHA256</span></h2>
  <p>Passwords hashed with PBKDF2-SHA256 + random salt. Minimum 8 characters enforced.</p>
  <form method="POST" action="/register">
    <input name="username" placeholder="Username"><br>
    <input name="password" type="password" placeholder="Password (min 8 chars)"><br><br>
    <button>Register</button>
  </form>
</div>
<p>Session: <b>{{{{ session.get('user','not logged in') }}}}</b></p>
</body></html>"""

COMMENTS_HTML = f"""<!DOCTYPE html><html><head><title>Comments</title>{STYLE}</head><body>
<h1>&#128274; SecureBank</h1>{NAV}<hr>
<div class="card">
  <h2>Comments <span class="fb">FIX #2: XSS Escaped</span></h2>
  <p>Script tags will be displayed as text, not executed.</p>
  <form method="POST">
    <input name="author" placeholder="Name">
    <input name="content" placeholder="Comment..." style="width:320px">
    <button>Post</button>
  </form>
</div>
{{% for c in comments %}}
<div class="card" style="border-left:4px solid #27ae60">
  <b>{{{{ c[1] }}}}</b>: {{{{ c[2] }}}}
</div>
{{% endfor %}}
</body></html>"""

PING_HTML = f"""<!DOCTYPE html><html><head><title>Ping</title>{STYLE}</head><body>
<h1>&#128274; SecureBank</h1>{NAV}<hr>
<div class="card">
  <h2>Network Ping <span class="fb">FIX #4: Command Injection Blocked</span></h2>
  <p>Only valid hostnames/IPs accepted. Shell metacharacters rejected.</p>
  <form method="POST">
    <input name="host" placeholder="e.g. 127.0.0.1" style="width:300px">
    <button>Ping</button>
  </form>
  {{% if error %}}<p style="color:red">{{{{ error }}}}</p>{{% endif %}}
</div>
{{% if output %}}<pre>{{{{ output }}}}</pre>{{% endif %}}
</body></html>"""

USER_HTML = f"""<!DOCTYPE html><html><head><title>Profile</title>{STYLE}</head><body>
<h1>&#128274; SecureBank</h1>{NAV}<hr>
<div class="card">
  <h2>User Profile <span class="fb">FIX #5: Auth Check Enforced</span></h2>
  <table>
    <tr><td><b>ID</b></td><td>{{{{ u[0] }}}}</td></tr>
    <tr><td><b>Username</b></td><td>{{{{ u[1] }}}}</td></tr>
    <tr><td><b>Email</b></td><td>{{{{ u[3] }}}}</td></tr>
    <tr><td><b>Balance</b></td><td>${{{{ u[5] }}}}</td></tr>
    <tr><td><b>Role</b></td><td>{{{{ u[4] }}}}</td></tr>
  </table>
</div>
</body></html>"""

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template_string(HOME_HTML, session=session)


# ════ FIX 1: PARAMETERIZED QUERY ════════════════════════════════════════════
# ? placeholder keeps SQL structure separate from data — injection impossible.
@app.route("/login", methods=["POST"])
def login():
    # FIX 3: rate limiting
    if is_rate_limited(request.remote_addr):
        return jsonify({"status": "error", "message": "Too many attempts. Wait 60 s."}), 429

    u = request.form["username"]
    p = request.form["password"]

    conn = sqlite3.connect(DB_PATH)
    # FIX 1: parameterized — u is data, never SQL
    row = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    conn.close()

    # FIX 3: PBKDF2 constant-time verify
    if row and verify_password(row[2], p):
        session["user"] = row[1]; session["uid"] = row[0]; session["role"] = row[3]
        return jsonify({"status": "success", "user": row[1], "role": row[3]})
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# ════ FIX 2: XSS PREVENTION ═════════════════════════════════════════════════
# No |safe in template → Jinja2 auto-escaping converts < to &lt; etc.
# <script>alert(1)</script> renders as visible text, never executes.
@app.route("/comments", methods=["GET", "POST"])
def comments():
    conn = sqlite3.connect(DB_PATH)
    if request.method == "POST":
        author  = request.form.get("author",  "Anon")[:100]
        content = request.form.get("content", "")[:1000]
        # FIX 2: stored as-is; escaping happens at render time via Jinja2
        conn.execute("INSERT INTO comments (author,content) VALUES (?,?)", (author, content))
        conn.commit()
    rows = conn.execute("SELECT * FROM comments").fetchall()
    conn.close()
    # FIX 2: template uses {{ c[2] }} WITHOUT |safe → auto-escaped
    return render_template_string(COMMENTS_HTML, comments=rows)


# ════ FIX 3: SECURE REGISTRATION ════════════════════════════════════════════
# PBKDF2-SHA256 with random salt; minimum 8-char password enforced.
@app.route("/register", methods=["POST"])
def register():
    u = request.form["username"]
    p = request.form["password"]

    if len(p) < 8:
        return jsonify({"status": "error", "message": "Password must be at least 8 characters"}), 400

    # FIX 3: strong adaptive hash — slow by design, unique salt per user
    ph = hash_password(p)

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("INSERT INTO users (username,password) VALUES (?,?)", (u, ph))
        conn.commit()
        return jsonify({"status": "registered"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Username taken"}), 400
    finally:
        conn.close()


# ════ FIX 4: COMMAND INJECTION PREVENTION ═══════════════════════════════════
# Strict allowlist regex — only valid IPs and hostnames pass.
# subprocess called with a list (no shell=True) so no shell expansion occurs.
SAFE_HOST = re.compile(r'^[a-zA-Z0-9.\-]{1,253}$')

@app.route("/ping", methods=["GET", "POST"])
def ping():
    output = error = ""
    if request.method == "POST":
        host = request.form.get("host", "").strip()
        # FIX 4: allowlist validation — reject anything with shell metacharacters
        if not SAFE_HOST.match(host):
            error = "Invalid host. Only alphanumeric characters, dots, and hyphens allowed."
        else:
            # FIX 4: list form + shell=False — shell never interprets the arguments
            result = subprocess.run(
                ["ping", "-c", "2", host],
                shell=False, capture_output=True, text=True, timeout=10
            )
            output = result.stdout + result.stderr
    return render_template_string(PING_HTML, output=output, error=error)


# ════ FIX 5: IDOR PREVENTION ════════════════════════════════════════════════
# User must be logged in AND can only view their own profile (unless admin).
@app.route("/user/<int:uid>")
def user_profile(uid):
    # FIX 5: must be authenticated
    if "uid" not in session:
        return jsonify({"error": "Login required"}), 401

    # FIX 5: only allow access to own profile, or admin can view any
    if session["uid"] != uid and session.get("role") != "admin":
        return jsonify({"error": "Access denied. You can only view your own profile."}), 403

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id,username,password,email,role,balance FROM users WHERE id=?", (uid,)
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "User not found"}), 404
    return render_template_string(USER_HTML, u=row)


@app.route("/reset")
def reset():
    if os.path.exists(DB_PATH): os.remove(DB_PATH)
    init_db()
    return jsonify({"status": "db reset"})


if __name__ == "__main__":
    init_db()
    app.run(debug=False, port=5001)
