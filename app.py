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
from flask import Flask, render_template_string, abort, flash, redirect, url_for
from flask_wtf.csrf import CSRFProtect

# python-dotenv loads variables from a .env file into os.environ so that
# secrets and configuration never have to be hardcoded in source files.
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# CSRF protection: requires a SECRET_KEY from environment or a generated ephemeral key.
# In production, set FLASK_SECRET_KEY in your .env file to a strong random value.
# If not set, Flask-WTF will generate an ephemeral key (secure but changes on restart).
app.config["SECRET_KEY"] = os.environ.get(
    "FLASK_SECRET_KEY",
    os.urandom(32).hex() if not os.environ.get("FLASK_ENV") == "production" else None
)
if not app.config["SECRET_KEY"]:
    raise RuntimeError(
        "FLASK_SECRET_KEY must be set in production. "
        "Please configure it in your .env file before starting the app."
    )

# Enable CSRF protection globally
CSRFProtect(app)

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

# The template is kept inline for simplicity (no extra files to deploy).
# Jinja2 auto-escapes variables in HTML context, which prevents XSS.
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Epikur Systemd Controller</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, sans-serif;
      background: #f0f2f5;
      color: #1a1a2e;
    }
    header {
      background: #16213e;
      color: #e0e0e0;
      padding: 1rem 2rem;
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    header h1 { margin: 0; font-size: 1.4rem; font-weight: 600; }
    main { padding: 2rem; max-width: 860px; margin: auto; }
    .card {
      background: #fff;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,.08);
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 1rem;
    }
    .service-name { font-size: 1.1rem; font-weight: 600; }
    .badge {
      display: inline-block;
      padding: .3rem .8rem;
      border-radius: 999px;
      font-size: .85rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: .05em;
    }
    .badge-active   { background: #d4edda; color: #155724; }
    .badge-inactive { background: #f8d7da; color: #721c24; }
    .badge-unknown  { background: #e2e3e5; color: #383d41; }
    form { margin: 0; }
    button {
      background: #0f3460;
      color: #fff;
      border: none;
      border-radius: 6px;
      padding: .55rem 1.3rem;
      font-size: .95rem;
      cursor: pointer;
      transition: background .2s;
    }
    button:hover { background: #1a5276; }
    .flash {
      padding: .8rem 1.2rem;
      border-radius: 6px;
      margin-bottom: 1rem;
      font-weight: 500;
    }
    .flash-success { background: #d4edda; color: #155724; }
    .flash-error   { background: #f8d7da; color: #721c24; }
    footer {
      text-align: center;
      padding: 2rem;
      font-size: .8rem;
      color: #888;
    }
  </style>
</head>
<body>
  <header>
    <h1>⚕ Epikur Systemd Controller</h1>
  </header>
  <main>
    {% if message %}
      <div class="flash flash-{{ message_type }}">{{ message }}</div>
    {% endif %}

    {% for service in services %}
      {% set status = statuses[service] %}
      <div class="card">
        <div>
          <div class="service-name">{{ service }}</div>
          <span class="badge
            {%- if status == 'active' %} badge-active
            {%- elif status == 'inactive' or status == 'failed' %} badge-inactive
            {%- else %} badge-unknown
            {%- endif %}">
            {{ status }}
          </span>
        </div>
        <form action="{{ url_for('restart', service=service) }}" method="post">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <button type="submit">↺ Restart</button>
        </form>
      </div>
    {% endfor %}
  </main>
  <footer>epikur-systemd-controller &mdash; internal use only</footer>
  <script>
    const BADGE_CLASSES = {
      active:   'badge-active',
      inactive: 'badge-inactive',
      failed:   'badge-inactive',
    };
    function refreshStatuses() {
      fetch('/status')
        .then(r => r.json())
        .then(data => {
          document.querySelectorAll('.card').forEach(card => {
            const name  = card.querySelector('.service-name').textContent.trim();
            const badge = card.querySelector('.badge');
            if (!badge || !(name in data)) return;
            const status = data[name];
            badge.textContent = status;
            badge.className = 'badge ' + (BADGE_CLASSES[status] ?? 'badge-unknown');
          });
        })
        .catch(() => { /* silently ignore transient network errors */ });
    }
    setInterval(refreshStatuses, 10000);
  </script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Dashboard: show the status of every allowed service."""
    statuses = {svc: get_service_status(svc) for svc in ALLOWED_SERVICES}
    # Flask's get_flashed_messages() returns a list; extract the first message if present.
    messages = list(flask.get_flashed_messages(with_categories=True))
    message = messages[0][1] if messages else None
    message_type = messages[0][0] if messages else None
    return render_template_string(
        DASHBOARD_TEMPLATE,
        services=ALLOWED_SERVICES,
        statuses=statuses,
        message=message,
        message_type=message_type,
    )


@app.route("/status")
def status():
    """Return current status of all allowed services as JSON (used by the polling script)."""
    return flask.jsonify({svc: get_service_status(svc) for svc in ALLOWED_SERVICES})


@app.route("/restart/<service>", methods=["POST"])
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

    if success:
        message = f"Service '{service}' restarted successfully."
        flash(message, category="success")
    else:
        message = f"Failed to restart '{service}'. Check the system journal for details."
        flash(message, category="error")

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
