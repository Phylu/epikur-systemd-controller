"""
epikur-systemd-controller — Flask-based web dashboard for monitoring and
restarting systemd services on a headless Linux server.

Security considerations implemented here:
  - No shell=True: all subprocess calls use argument lists to prevent
    shell injection attacks.
  - Allowlist validation: every service name supplied by the user (via
    the URL/form) is checked against ALLOWED_SERVICES loaded from the
    .env file.  Requests for unlisted services are rejected with 403.
  - Subprocess output is captured but never evaluated or executed.
"""

import os
import subprocess
import flask
from flask import Flask, render_template, abort, flash, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

# python-dotenv loads variables from a .env file into os.environ so that
# secrets and configuration never have to be hardcoded in source files.
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# CSRF protection requires a strong, stable SECRET_KEY shared across all
# Gunicorn workers.  An ephemeral per-worker key would invalidate CSRF tokens
# on every restart and break requests handled by a different worker.
# Always set FLASK_SECRET_KEY in your .env file.
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError(
        "FLASK_SECRET_KEY must be set. "
        "Generate a key with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
if "CHANGE_ME" in str(app.config["SECRET_KEY"]):
    raise RuntimeError(
        "FLASK_SECRET_KEY must not contain a placeholder value. "
        "Generate a real key and set it in your .env file before starting the app."
    )

# Enable CSRF protection globally
CSRFProtect(app)


@app.after_request
def _set_security_headers(response: flask.Response) -> flask.Response:
    """Apply defensive HTTP headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    # 'unsafe-inline' is required because the template uses inline <script> and
    # <style> blocks.  All user-controlled values pass through Jinja2 auto-escaping
    # so the XSS risk is already mitigated at the template layer.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none';"
    )
    return response

# ---------------------------------------------------------------------------
# HTTP Basic Auth
# ---------------------------------------------------------------------------

# Credentials are loaded from the .env file.  Example entries:
#   BASIC_AUTH_USERNAME=admin
#   BASIC_AUTH_PASSWORD=changeme
#
# The password is stored as a Werkzeug password hash at startup so that the
# plaintext value is not kept in memory after the hash is generated.
_auth_username = os.environ.get("BASIC_AUTH_USERNAME", "")
_auth_password = os.environ.get("BASIC_AUTH_PASSWORD", "")
if not _auth_username or not _auth_password:
    raise RuntimeError(
        "BASIC_AUTH_USERNAME and BASIC_AUTH_PASSWORD must be set. "
        "Please configure them in your .env file before starting the app."
    )
_PLACEHOLDER = "CHANGE_ME"
if _PLACEHOLDER in _auth_username or _PLACEHOLDER in _auth_password:
    raise RuntimeError(
        "BASIC_AUTH_USERNAME and BASIC_AUTH_PASSWORD must not contain placeholder values. "
        "Set real credentials in your .env file before starting the app."
    )

auth = HTTPBasicAuth()
_users = {_auth_username: generate_password_hash(_auth_password)}
# Clear plaintext credentials from the environment after hashing so they are
# not visible to child processes or inspectable via /proc.
os.environ.pop("BASIC_AUTH_PASSWORD", None)
os.environ.pop("BASIC_AUTH_USERNAME", None)

# Dummy hash used to ensure verify_password always calls check_password_hash,
# preventing username enumeration through response-time differences.
_DUMMY_HASH = generate_password_hash("dummy-sentinel")


@auth.verify_password
def verify_password(username: str, password: str) -> bool:
    # Always look up a hash (real or dummy) so the response time does not
    # reveal whether the username exists — constant-time defence.
    hashed = _users.get(username, _DUMMY_HASH)
    if check_password_hash(hashed, password) and username in _users:
        return True
    app.logger.warning("Failed Basic Auth attempt for username: %r", username)
    return False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# ALLOWED_SERVICES is a comma-separated list of systemd service names that
# this dashboard is permitted to query and restart.
# Example .env entry:  ALLOWED_SERVICES=epikur.service,nginx.service
raw_services = os.environ.get("ALLOWED_SERVICES", "")
ALLOWED_SERVICES: list[str] = [s.strip() for s in raw_services.split(",") if s.strip()]

# Fail loudly at startup if no services are configured – an empty allowlist
# would mean every validation check fails, which is confusing to operate.
if not ALLOWED_SERVICES:
    raise RuntimeError(
        "ALLOWED_SERVICES is not set or empty.  "
        "Please configure it in your .env file before starting the app."
    )

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_service(service: str) -> None:
    """
    Raise a 403 Forbidden abort if *service* is not in ALLOWED_SERVICES.

    This is the central allowlist gate.  It must be called before every
    subprocess invocation so that an attacker cannot craft a URL that
    executes an arbitrary systemctl command.
    """
    if service not in ALLOWED_SERVICES:
        # Log the attempt so it is visible in the Gunicorn/systemd journal.
        app.logger.warning("Rejected request for unlisted service: %r", service)
        abort(403)


def get_service_status(service: str) -> str:
    """
    Return the raw `systemctl is-active` status string for *service*.

    Typical values include `active`, `inactive`, `activating`,
    `deactivating`, `failed`, and `unknown`.  On timeout or OS-level
    execution errors, this function also returns `unknown`.

    No shell=True — the command and its arguments are passed as a list.
    """
    _validate_service(service)
    try:
        app.logger.info("AUDIT: systemctl is-active %s", service)
        result = subprocess.run(
            # Explicit list → no shell expansion, no injection risk.
            # Use the full path to systemctl (/usr/bin/systemctl on Debian/Ubuntu)
            # so that PATH manipulation cannot redirect the command.
            ["sudo", "-n", "/usr/bin/systemctl", "is-active", service],
            capture_output=True,
            text=True,
            timeout=10,  # seconds; prevents the request from hanging forever
        )
        # is-active prints exactly one of: active, inactive, activating,
        # deactivating, failed, unknown.
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        app.logger.error("Timeout while checking status of %s", service)
        return "unknown"
    except OSError as exc:
        app.logger.error("OS error while checking %s: %s", service, exc)
        return "unknown"


def restart_service(service: str) -> bool:
    """
    Restart *service* via `systemctl restart`.

    Returns True on success, False otherwise.  Again, no shell=True.
    """
    _validate_service(service)
    try:
        app.logger.info("AUDIT: systemctl restart %s", service)
        result = subprocess.run(
            ["sudo", "-n", "/usr/bin/systemctl", "restart", service],
            capture_output=True,
            text=True,
            timeout=30,  # restarts can take a few seconds
        )
        success = result.returncode == 0
        if not success:
            app.logger.error(
                "Restart of %s failed (rc=%d): %s",
                service,
                result.returncode,
                result.stderr.strip(),
            )
        return success
    except subprocess.TimeoutExpired:
        app.logger.error("Timeout while restarting %s", service)
        return False
    except OSError as exc:
        app.logger.error("OS error while restarting %s: %s", service, exc)
        return False


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

# Human-readable display names for known services.
SERVICE_DISPLAY_NAMES = {
    "epikur.service": "Epikur-Server",
}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
@auth.login_required
def index():
    """Dashboard: show the status of every allowed service."""
    statuses = {svc: get_service_status(svc) for svc in ALLOWED_SERVICES}
    # Flask's get_flashed_messages() returns a list; extract the first message if present.
    messages = list(flask.get_flashed_messages(with_categories=True))
    message = messages[0][1] if messages else None
    message_type = messages[0][0] if messages else None
    return render_template("dashboard.html",
        services=ALLOWED_SERVICES,
        statuses=statuses,
        display_names=SERVICE_DISPLAY_NAMES,
        message=message,
        message_type=message_type,
    )


@app.route("/status")
@auth.login_required
def status():
    """Return current status of all allowed services as JSON (used by the polling script)."""
    return flask.jsonify({svc: get_service_status(svc) for svc in ALLOWED_SERVICES})


@app.route("/restart/<service>", methods=["POST"])
@auth.login_required
def restart(service: str):
    """
    Restart a single service using POST/Redirect/GET pattern.

    Only POST is accepted to prevent accidental restarts via a bookmarked
    GET link or a browser pre-fetch.  The service name is validated against
    ALLOWED_SERVICES inside restart_service() before any system call is made.
    
    After attempting the restart, this route redirects back to the dashboard
    with a flash message indicating success or failure.  This prevents form
    resubmission on page refresh.
    """
    # _validate_service is called inside restart_service, but we call it here
    # first so we can return a clean error page rather than an OS exception.
    _validate_service(service)

    success = restart_service(service)

    display_name = SERVICE_DISPLAY_NAMES.get(service, service)
    if success:
        flash(
            f"Der {display_name} wurde erfolgreich neu gestartet. "
            f"Bitte warte etwa 30 Sekunden, bevor du dich erneut verbindest.",
            category="success",
        )
    else:
        flash(
            f"Der {display_name} konnte leider nicht neu gestartet werden. "
            f"Bitte wende dich an den IT-Administrator der Praxis.",
            category="error",
        )

    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Entry point (development only)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # This block is only reached when running `python app.py` directly.
    # In production, Gunicorn serves the `app` object and this block is
    # never executed.
    port = int(os.environ.get("FLASK_PORT", 5000))
    # debug=False even in dev mode to avoid accidentally leaking tracebacks
    # if this file is run on a production server.
    app.run(host="127.0.0.1", port=port, debug=False)
