""" 
Group Members :
Maryam Khan CR-22021
Ayesha Yousuf CR-22004
                                             Automated Security Tests                                                               """

import pytest
import sys
import os
import sqlite3
import hashlib

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ─── App loader ───────────────────────────────────────────────────────────────
def load_app(name, path, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import importlib.util
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.init_db()
    mod.app.config["TESTING"] = True
    return mod

# ─── Fixtures ─────────────────────────────────────────────────────────────────
@pytest.fixture
def vuln(tmp_path, monkeypatch):
    mod = load_app("vuln_app", os.path.join(BASE, "vulnerable", "app.py"), tmp_path, monkeypatch)
    with mod.app.test_client() as client:
        yield client, mod, tmp_path

@pytest.fixture
def fixed(tmp_path, monkeypatch):
    mod = load_app("fixed_app", os.path.join(BASE, "fixed", "app.py"), tmp_path, monkeypatch)
    with mod.app.test_client() as client:
        yield client, mod, tmp_path


# ═════════════════════════════════════════════════════════════════════════════
# TEST CLASS 1 — SQL INJECTION
# ═════════════════════════════════════════════════════════════════════════════
class TestSQLInjection:
    """
    Attack: username = ' OR '1'='1'--
    Transforms query into: WHERE username='' OR '1'='1'-- AND password='...'
    The '--' comments out the password check; OR '1'='1' always returns rows.
    Fix: Parameterized query with ? placeholder.
    """

    PAYLOAD = "' OR '1'='1'--"

    def test_sqli_attack_VULNERABLE(self, vuln):
        """SQLi bypasses auth → status=success on vulnerable app."""
        client, _, _ = vuln
        r = client.post("/login", data={"username": self.PAYLOAD, "password": "wrong"})
        d = r.get_json()
        assert r.status_code == 200 and d.get("status") == "success", \
            f"SQLi must bypass auth on vulnerable app. Got {r.status_code}: {d}"
        print(f"\n  ✓ [VULN] SQLi logged in as: {d.get('user')}")

    def test_sqli_blocked_FIXED(self, fixed):
        """Parameterized query treats payload as literal string → 401."""
        client, _, _ = fixed
        r = client.post("/login", data={"username": self.PAYLOAD, "password": "wrong"})
        d = r.get_json()
        assert r.status_code == 401, \
            f"Fixed app must reject SQLi. Got {r.status_code}: {d}"
        print(f"\n  ✓ [FIX] SQLi blocked → 401 Unauthorized")

    def test_legitimate_login_FIXED(self, fixed):
        """Correct credentials still succeed in the fixed version."""
        client, _, _ = fixed
        r = client.post("/login", data={"username": "admin", "password": "admin123"})
        assert r.get_json().get("status") == "success"
        print(f"\n  ✓ [SANITY] Legitimate login works on fixed app")


# ═════════════════════════════════════════════════════════════════════════════
# TEST CLASS 2 — CROSS-SITE SCRIPTING (XSS)
# ═════════════════════════════════════════════════════════════════════════════
class TestXSS:
    """
    Attack: Store <script>alert(document.cookie)</script> in a comment.
    Vulnerable: |safe disables Jinja2 escaping → script tag executes in browser.
    Fix: Remove |safe → Jinja2 auto-escapes <script> to &lt;script&gt;.
    """

    PAYLOAD = "<script>alert('XSS_ATTACK')</script>"

    def test_xss_executes_VULNERABLE(self, vuln):
        """Raw <script> tag appears in vulnerable response HTML."""
        client, _, _ = vuln
        client.post("/comments", data={"author": "att", "content": self.PAYLOAD})
        html = client.get("/comments").data.decode()
        assert self.PAYLOAD in html, "Raw <script> must be in vulnerable response"
        print(f"\n  ✓ [VULN] Raw <script> tag found in HTML → XSS executes")

    def test_xss_escaped_FIXED(self, fixed):
        """Script tag is escaped to &lt;script&gt; in fixed response."""
        client, _, _ = fixed
        client.post("/comments", data={"author": "att", "content": self.PAYLOAD})
        html = client.get("/comments").data.decode()
        assert self.PAYLOAD not in html, "Raw <script> must NOT appear in fixed response"
        assert "&lt;script&gt;" in html, "&lt;script&gt; must appear as escaped text"
        print(f"\n  ✓ [FIX] XSS escaped → &lt;script&gt; displayed as text, not executed")

    def test_normal_comment_FIXED(self, fixed):
        """Regular comments still display correctly after the fix."""
        client, _, _ = fixed
        client.post("/comments", data={"author": "alice", "content": "Great product!"})
        html = client.get("/comments").data.decode()
        assert "Great product!" in html
        print(f"\n  ✓ [SANITY] Normal comments render correctly")


# ═════════════════════════════════════════════════════════════════════════════
# TEST CLASS 3 — BROKEN AUTHENTICATION
# ═════════════════════════════════════════════════════════════════════════════
class TestBrokenAuthentication:
    """
    Attacks:
      (a) DB dump → MD5('password') matches crackstation.net in seconds.
      (b) No brute-force protection → unlimited login attempts.
    Fix:
      (a) PBKDF2-SHA256 with random 16-byte salt (stored as salt:hash).
      (b) Max 5 attempts per IP per 60 seconds → HTTP 429.
    """

    def test_md5_hash_stored_VULNERABLE(self, vuln):
        """Vulnerable app stores unsalted MD5 — 32 hex chars, rainbow-table crackable."""
        client, _, tmp_path = vuln
        client.post("/register", data={"username": "testv", "password": "password"})
        db = tmp_path / "vuln.db"
        if not db.exists(): pytest.skip("DB not accessible")
        row = sqlite3.connect(str(db)).execute(
            "SELECT password FROM users WHERE username='testv'").fetchone()
        if not row: pytest.skip("User not created")
        stored = row[0]
        assert stored == hashlib.md5(b"password").hexdigest(), \
            f"Expected MD5 hash, got: {stored}"
        assert len(stored) == 32
        print(f"\n  ✓ [VULN] MD5 hash stored: {stored}  ← in every rainbow table")

    def test_pbkdf2_hash_stored_FIXED(self, fixed):
        """Fixed app stores PBKDF2-SHA256 with salt (salt_hex:dk_hex)."""
        client, _, tmp_path = fixed
        client.post("/register", data={"username": "testf", "password": "securePass1"})
        db = tmp_path / "fixed.db"
        if not db.exists(): pytest.skip("DB not accessible")
        row = sqlite3.connect(str(db)).execute(
            "SELECT password FROM users WHERE username='testf'").fetchone()
        if not row: pytest.skip("User not created")
        stored = row[0]
        assert ":" in stored, f"PBKDF2 must use salt:hash format, got: {stored}"
        salt_hex, dk_hex = stored.split(":", 1)
        assert len(salt_hex) == 32,  "Salt should be 16 bytes (32 hex chars)"
        assert len(dk_hex)   == 64,  "SHA-256 digest should be 32 bytes (64 hex chars)"
        # Verify the stored hash validates correctly
        dk = hashlib.pbkdf2_hmac("sha256", b"securePass1",
                                  bytes.fromhex(salt_hex), 260_000)
        assert dk.hex() == dk_hex, "PBKDF2 verify must pass for correct password"
        print(f"\n  ✓ [FIX] PBKDF2 hash with unique salt: {salt_hex[:8]}...:{dk_hex[:8]}...")

    def test_same_password_different_hashes_FIXED(self, fixed):
        """Same password for two users → different hashes (unique salts). Defeats rainbow tables."""
        client, _, tmp_path = fixed
        client.post("/register", data={"username": "ua", "password": "samePass99"})
        client.post("/register", data={"username": "ub", "password": "samePass99"})
        db = tmp_path / "fixed.db"
        if not db.exists(): pytest.skip("DB not accessible")
        rows = sqlite3.connect(str(db)).execute(
            "SELECT password FROM users WHERE username IN ('ua','ub')").fetchall()
        if len(rows) < 2: pytest.skip("Users not created")
        assert rows[0][0] != rows[1][0], \
            "Identical passwords must produce different hashes (salt is random per user)"
        print(f"\n  ✓ [FIX] Unique salts confirmed — rainbow table attack defeated")

    def test_no_rate_limiting_VULNERABLE(self, vuln):
        """Vulnerable app never returns 429 — brute force has no limit."""
        client, _, _ = vuln
        for i in range(10):
            r = client.post("/login", data={"username": "admin", "password": f"wrong{i}"})
            assert r.status_code != 429, \
                f"Vulnerable app should not rate-limit (attempt {i+1})"
        print(f"\n  ✓ [VULN] No rate limiting — 10 attempts, no lockout")

    def test_rate_limiting_FIXED(self, fixed):
        """Fixed app returns 429 after 5 failed attempts (brute force blocked)."""
        client, _, _ = fixed
        for _ in range(5):
            client.post("/login", data={"username": "admin", "password": "wrong"})
        r = client.post("/login", data={"username": "admin", "password": "wrong"})
        assert r.status_code == 429, f"Expected 429 after 6 attempts, got {r.status_code}"
        print(f"\n  ✓ [FIX] Rate limiting → 429 Too Many Requests after 5 attempts")

    def test_short_password_rejected_FIXED(self, fixed):
        """Fixed app enforces minimum password length of 8 characters."""
        client, _, _ = fixed
        r = client.post("/register", data={"username": "weakuser", "password": "abc"})
        assert r.status_code == 400
        assert "8" in r.get_json().get("message", "")
        print(f"\n  ✓ [FIX] Short password (3 chars) rejected with 400")


# ═════════════════════════════════════════════════════════════════════════════
# TEST CLASS 4 — COMMAND INJECTION
# ═════════════════════════════════════════════════════════════════════════════
class TestCommandInjection:
    """
    Attack: host = "127.0.0.1; id"
    Vulnerable: shell=True runs the injected command after the semicolon.
    Fix: Allowlist regex (only [a-zA-Z0-9.-]) + shell=False (list form).
    """

    # Cross-platform payloads: "echo" works on both Linux and Windows.
    # Base command is now "echo Checking: <host>" so semicolon/&& chain a second echo.
    PAYLOAD_SEMICOLON = "safe; echo INJECTED"
    PAYLOAD_AND       = "safe && echo INJECTED"
    PAYLOAD_PIPE      = "safe | echo INJECTED"

    def _ping(self, client, host):
        return client.post("/ping", data={"host": host})

    def test_cmd_injection_semicolon_VULNERABLE(self, vuln):
        """Semicolon chains a second command — output appears in vulnerable response."""
        client, _, _ = vuln
        r = self._ping(client, self.PAYLOAD_SEMICOLON)
        assert "INJECTED" in r.data.decode(), \
            "Semicolon injection must execute on vulnerable app"
        print(f"\n  ✓ [VULN] Semicolon injection → 'INJECTED' in output")

    def test_cmd_injection_and_VULNERABLE(self, vuln):
        """&& chains a second command — output appears in vulnerable response."""
        client, _, _ = vuln
        r = self._ping(client, self.PAYLOAD_AND)
        assert "INJECTED" in r.data.decode(), \
            "&& injection must execute on vulnerable app"
        print(f"\n  ✓ [VULN] && injection → 'INJECTED' in output")

    def test_cmd_injection_blocked_FIXED(self, fixed):
        """Shell metacharacters rejected by allowlist regex — no command runs."""
        client, _, _ = fixed
        for payload in [self.PAYLOAD_SEMICOLON, self.PAYLOAD_AND, self.PAYLOAD_PIPE]:
            r = self._ping(client, payload)
            html = r.data.decode()
            assert "INJECTED" not in html, \
                f"Injected output must not appear in fixed response for payload: {payload}"
            assert "Invalid host" in html or "error" in html.lower(), \
                "Fixed app should show validation error"
        print(f"\n  ✓ [FIX] All injection payloads rejected by allowlist")

    def test_valid_host_FIXED(self, fixed):
        """Clean hostname passes allowlist validation in fixed app."""
        client, _, _ = fixed
        r = self._ping(client, "localhost")
        html = r.data.decode()
        assert "Invalid host" not in html, \
            "Valid hostname should pass allowlist validation"
        print(f"\n  ✓ [SANITY] Valid host passes allowlist")


# ═════════════════════════════════════════════════════════════════════════════
# TEST CLASS 5 — IDOR (Insecure Direct Object Reference)
# ═════════════════════════════════════════════════════════════════════════════
class TestIDOR:
    """
    Attack: Visit /user/2 or /user/3 as an unauthenticated user (or as alice trying to see bob).
    Vulnerable: No auth check — any visitor can view any user's email and balance.
    Fix: Session check (must be logged in) + ownership check (uid must match, unless admin).
    """

    def test_idor_unauth_access_VULNERABLE(self, vuln):
        """Unauthenticated user can fetch any user profile on vulnerable app."""
        client, _, _ = vuln
        for uid in [1, 2, 3]:
            r = client.get(f"/user/{uid}")
            assert r.status_code == 200, \
                f"Unauthenticated access to /user/{uid} must succeed on vulnerable app"
            html = r.data.decode()
            # Sensitive data is exposed
            assert "vulnbank.com" in html, f"Email exposed for user {uid}"
        print(f"\n  ✓ [VULN] All 3 user profiles accessible without login")

    def test_idor_cross_user_VULNERABLE(self, vuln):
        """Alice (logged in as uid 2) can fetch Bob's profile (uid 3) — no ownership check."""
        client, _, _ = vuln
        # Log in as alice
        client.post("/login", data={"username": "alice", "password": "password"})
        r = client.get("/user/3")   # Bob's profile
        assert r.status_code == 200
        html = r.data.decode()
        assert "bob" in html.lower() or "securebank" in html.lower() or "vulnbank" in html.lower(), \
            "Alice must see Bob's profile on vulnerable app"
        print(f"\n  ✓ [VULN] Alice accessed Bob's profile — IDOR confirmed")

    def test_idor_unauth_blocked_FIXED(self, fixed):
        """Unauthenticated request returns 401 on fixed app."""
        client, _, _ = fixed
        r = client.get("/user/1")
        assert r.status_code == 401, \
            f"Fixed app must require login. Got {r.status_code}"
        print(f"\n  ✓ [FIX] Unauthenticated access → 401 Login Required")

    def test_idor_cross_user_blocked_FIXED(self, fixed):
        """Alice cannot view Bob's profile on fixed app — returns 403."""
        client, _, _ = fixed
        client.post("/login", data={"username": "alice", "password": "password"})
        r = client.get("/user/3")   # Bob's profile (alice is uid 2)
        assert r.status_code == 403, \
            f"Fixed app must deny cross-user access. Got {r.status_code}"
        print(f"\n  ✓ [FIX] Cross-user access → 403 Access Denied")

    def test_own_profile_works_FIXED(self, fixed):
        """User can access their own profile after logging in (fix doesn't break normal use)."""
        client, _, _ = fixed
        r = client.post("/login", data={"username": "alice", "password": "password"})
        uid = r.get_json().get("user")   # alice is uid 2
        # Find alice's actual uid
        r2 = client.get("/user/2")
        assert r2.status_code == 200, \
            f"Alice must be able to view her own profile. Got {r2.status_code}"
        print(f"\n  ✓ [SANITY] User can view their own profile on fixed app")

    def test_admin_can_view_any_FIXED(self, fixed):
        """Admin can view any user profile (authorization, not just authentication)."""
        client, _, _ = fixed
        client.post("/login", data={"username": "admin", "password": "admin123"})
        for uid in [1, 2, 3]:
            r = client.get(f"/user/{uid}")
            assert r.status_code == 200, \
                f"Admin must be able to view /user/{uid}. Got {r.status_code}"
        print(f"\n  ✓ [SANITY] Admin can view all profiles")


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
