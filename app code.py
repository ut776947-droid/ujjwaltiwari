"""
Zero-Trust Network Access: Cloudflare Tunnels and MFA
Educational demonstration Flask admin console.

Security model:
1. Cloudflare Tunnel publishes the app without opening inbound firewall ports.
2. Cloudflare Access protects the hostname and enforces identity/MFA policies.
3. This demo app adds TOTP-based MFA for defense in depth.
4. Keep the app bound to localhost and do not expose it directly to the Internet.

This is a demonstration scaffold, not a production-ready identity system.
"""
import os
import time
import secrets
from functools import wraps
from collections import defaultdict, deque

import pyotp
from flask import Flask, abort, flash, redirect, render_template_string, request, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=900,
)

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
MFA_SECRET = os.environ.get("MFA_SECRET", "")
ACCESS_EMAIL_HEADER = os.environ.get("CF_ACCESS_EMAIL_HEADER", "Cf-Access-Authenticated-User-Email")
REQUIRE_CLOUDFLARE_ACCESS_HEADER = os.environ.get("REQUIRE_CLOUDFLARE_ACCESS_HEADER", "0") == "1"

# Simple in-memory rate limiting for the teaching demo. Use a shared store / gateway
# rate limiting for multi-worker or production deployments.
LOGIN_ATTEMPTS = defaultdict(deque)
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300

LOGIN_HTML = """
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure Admin Console</title>
<style>
body{font-family:system-ui,Arial;margin:0;background:#eef3f8;color:#172334}
main{max-width:440px;margin:7vh auto;padding:28px;background:white;border-radius:16px;
box-shadow:0 10px 32px #17233418}h1{margin-top:0;color:#b5121b}
label{display:block;margin:14px 0 6px;font-weight:600}
input{box-sizing:border-box;width:100%;padding:11px;border:1px solid #bdc8d5;border-radius:8px}
button{margin-top:18px;padding:11px 16px;background:#b5121b;color:white;border:0;border-radius:8px;
font-weight:700;cursor:pointer}.note{font-size:.9rem;color:#526174}.flash{padding:10px;background:#fff2d8;border-radius:8px}
</style></head><body><main><h1>Admin Console</h1>
<p class="note">Protected by Cloudflare Access and an additional time-based one-time password (TOTP).</p>
{% with messages = get_flashed_messages() %}{% for message in messages %}<p class="flash">{{ message }}</p>{% endfor %}{% endwith %}
<form method="post">
<label for="username">Username</label><input id="username" name="username" autocomplete="username" required>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
<label for="otp">Authenticator code</label><input id="otp" name="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required>
<button type="submit">Sign in securely</button></form>
<p class="note">Demo only. Use a unique password, secret key, and MFA secret from environment variables.</p>
</main></body></html>
"""

DASHBOARD_HTML = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure Admin Dashboard</title><style>
body{font-family:system-ui,Arial;margin:0;background:#eef3f8;color:#172334}
main{max-width:850px;margin:5vh auto;padding:28px;background:white;border-radius:16px;box-shadow:0 10px 32px #17233418}
h1{color:#b5121b}.badge{display:inline-block;padding:5px 10px;background:#e0f6e9;color:#17633a;border-radius:999px}
.card{padding:16px;border:1px solid #dbe3ec;border-radius:10px;margin:12px 0}
a{color:#a10e18}button{padding:9px 14px;background:#b5121b;color:white;border:0;border-radius:8px}
</style></head><body><main><h1>Zero-Trust Admin Dashboard</h1>
<p class="badge">Authenticated session</p>
<div class="card"><strong>Identity</strong><p>{{ identity }}</p></div>
<div class="card"><strong>Access layers</strong><ul><li>Cloudflare Tunnel: outbound-only connector</li>
<li>Cloudflare Access: identity and MFA policy (configure in dashboard)</li>
<li>Application MFA: TOTP verified by this demo</li><li>Session cookie: HttpOnly and SameSite</li></ul></div>
<div class="card"><strong>Security reminder</strong><p>This page is a demonstration. Do not store real secrets or sensitive admin data in the sample.</p></div>
<form method="post" action="{{ url_for('logout') }}"><button type="submit">Log out</button></form>
</main></body></html>
"""

def cloudflare_access_required(view):
    """Optional defense-in-depth presence check for the Access identity header.
    Only enable this when the origin is reachable exclusively through Cloudflare
    Access/Tunnel. A header alone is not cryptographic proof if direct access exists.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        if REQUIRE_CLOUDFLARE_ACCESS_HEADER and not request.headers.get(ACCESS_EMAIL_HEADER):
            abort(403, "Cloudflare Access identity header missing.")
        return view(*args, **kwargs)
    return wrapped

def rate_limited(ip):
    now = time.time()
    attempts = LOGIN_ATTEMPTS[ip]
    while attempts and now - attempts[0] > WINDOW_SECONDS:
        attempts.popleft()
    return len(attempts) >= MAX_ATTEMPTS

@app.route("/", methods=["GET", "POST"])
@cloudflare_access_required
def login():
    if session.get("authenticated"):
        return redirect(url_for("dashboard"))

    ip = request.headers.get("CF-Connecting-IP", request.remote_addr or "unknown")
    if request.method == "POST":
        if rate_limited(ip):
            abort(429, "Too many login attempts. Try again in five minutes.")
        LOGIN_ATTEMPTS[ip].append(time.time())

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        otp = request.form.get("otp", "").strip()

        # Avoid running with a blank password or MFA secret.
        if not ADMIN_PASSWORD or not MFA_SECRET:
            flash("Server setup incomplete: set ADMIN_PASSWORD and MFA_SECRET in the environment.")
            return render_template_string(LOGIN_HTML), 503

        valid_password = secrets.compare_digest(username, ADMIN_USERNAME) and secrets.compare_digest(password, ADMIN_PASSWORD)
        valid_otp = pyotp.TOTP(MFA_SECRET).verify(otp, valid_window=1)

        if valid_password and valid_otp:
            session.clear()
            session["authenticated"] = True
            session["login_time"] = int(time.time())
            session.permanent = True
            LOGIN_ATTEMPTS.pop(ip, None)
            return redirect(url_for("dashboard"))

        # Do not disclose which factor failed.
        flash("Invalid credentials or authenticator code.")
    return render_template_string(LOGIN_HTML)

@app.route("/dashboard")
@cloudflare_access_required
def dashboard():
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    identity = request.headers.get(ACCESS_EMAIL_HEADER, "Cloudflare identity header not enabled")
    return render_template_string(DASHBOARD_HTML, identity=identity)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/health")
def health():
    """Minimal health endpoint; do not include secrets or internal configuration."""
    return {"status": "ok"}, 200

if __name__ == "__main__":
    # Keep the origin local. Publish through cloudflared, not Flask's public interface.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
