# epikur-systemd-controller

A lightweight, Flask-based web dashboard for monitoring and restarting specific
systemd services directly from a browser.  It was built to solve the problem of
**Epikur** (a German practice-management software) randomly crashing on headless
Linux servers, where the normal Java-GUI restart path is unavailable.  Staff in a
doctor's or psychotherapist's office can simply open a browser tab and click
**Restart** without needing SSH or remote-desktop access.

---

## Features

- **Live status** — displays `active` / `inactive` / `failed` for every
  configured service, refreshed on each page load.
- **One-click restart** — POST-only form submission prevents accidental
  restarts from bookmarks or browser pre-fetch.
- **Allowlist validation** — only services explicitly listed in `ALLOWED_SERVICES`
  can be queried or restarted; all other requests are rejected with HTTP 403.
- **No `shell=True`** — all `subprocess` calls use argument lists to eliminate
  shell-injection risk.
- **Configuration via `.env`** — service names are never hardcoded in the
  application logic.
- **Least-privilege sudoers** — the web process only gains the right to run
  `systemctl is-active` and `systemctl restart` for the specific services
  you configure.
- **Served by Gunicorn** — production-grade WSGI server with a systemd unit
  file included.

---

## ⚠️ Security / Disclaimer

> **Read this section carefully before deploying.**

1. **Do not expose this tool directly to the public internet.**
   Gunicorn has no built-in TLS or authentication.  Without a reverse proxy
   (e.g. Nginx with HTTPS and HTTP Basic Auth), anyone who can reach the port
   can restart your services.

2. **Use a reverse proxy with authentication.**
   Put Nginx (or Caddy/Apache) in front of Gunicorn, terminate TLS there, and
   add at minimum HTTP Basic Auth to restrict access.

3. **Bind to `127.0.0.1` (default).**
   The included systemd unit file binds Gunicorn to `127.0.0.1:5000` so it is
   only reachable from the same machine.  The reverse proxy then forwards
   traffic to it.  Only change to `0.0.0.0` if you are on a fully isolated,
   firewalled internal network and accept the risk.

4. **Keep `ALLOWED_SERVICES` minimal.**
   List only the services you actually need to control.  Every service you add
   increases the potential blast radius of a compromised dashboard.

5. **Validate the sudoers file with `visudo -c`** before activating it.
   A syntax error in `/etc/sudoers.d/` can lock you out of `sudo` entirely.

This software is provided **as-is**, without warranty of any kind.  The authors
are not responsible for damage caused by misconfiguration or misuse.

---

## Requirements

- Python 3.11 or newer
- A Linux system running systemd
- `sudo` configured as described below

---

## Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/Phylu/epikur-systemd-controller.git
cd epikur-systemd-controller
```

### 2. Create a Python virtual environment and install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure the application

```bash
cp .env.example .env
# Edit .env and set ALLOWED_SERVICES to the service(s) you want to control:
#   ALLOWED_SERVICES=epikur.service
nano .env
```

### 4. Configure sudoers (least-privilege access)

The web process runs as `www-data` and needs passwordless access to two
`systemctl` sub-commands for each allowed service.

```bash
# Copy the example sudoers drop-in
sudo cp sudoers.d/epikur /etc/sudoers.d/epikur

# Edit it to match the service names in your .env
sudo nano /etc/sudoers.d/epikur

# Set the required permissions
sudo chmod 0440 /etc/sudoers.d/epikur

# Validate the syntax — do this BEFORE relying on it
sudo visudo -c -f /etc/sudoers.d/epikur
```

### 5. Deploy the application files

```bash
sudo mkdir -p /opt/epikur-systemd-controller
sudo cp -r . /opt/epikur-systemd-controller/
sudo chown -R www-data:www-data /opt/epikur-systemd-controller
```

### 6. Install and start the systemd services

#### Epikur Java application (`epikur.service`)

`epikur.service` starts the Epikur JAR directly via the Java binary so that
systemd can track the PID natively and capture all output in the journal.

```bash
# Create the dedicated service account (once):
sudo useradd --system --no-create-home --shell /bin/false epikur
# (/bin/false is portable; use /usr/sbin/nologin or /usr/bin/nologin where preferred)

# Deploy the application files and set ownership:
sudo mkdir -p /opt/epikur
sudo cp /path/to/epikur.jar /opt/epikur/epikur.jar
sudo chown -R epikur:epikur /opt/epikur

# Install and enable the service:
sudo cp epikur.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now epikur.service

# Verify it is running and follow its journal:
sudo systemctl status epikur.service
journalctl -u epikur.service -f
```

> **Tip:** Adjust the `-Xmx` heap flag and the JAR path inside `epikur.service`
> to match your server's available RAM and installation directory before copying.

#### Epikur Systemd Controller (this dashboard — `epikur-systemd-controller.service`)

```bash
sudo cp epikur-systemd-controller.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now epikur-systemd-controller.service

# Verify it is running
sudo systemctl status epikur-systemd-controller.service
```

### 7. (Recommended) Set up a reverse proxy with Nginx

```nginx
server {
    listen 80;
    server_name controller.example.internal;

    # Redirect plain HTTP to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name controller.example.internal;

    ssl_certificate     /etc/ssl/certs/your-cert.pem;
    ssl_certificate_key /etc/ssl/private/your-key.pem;

    # Require HTTP Basic Auth
    auth_basic           "Epikur Controller";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
    }
}
```

---

## File structure

```
epikur-systemd-controller/
├── app.py                            # Flask application
├── .env.example                      # Configuration template (copy to .env)
├── requirements.txt                  # Python dependencies
├── epikur.service                    # systemd unit for the Epikur Java application
├── epikur-systemd-controller.service # systemd unit for Gunicorn (this dashboard)
├── sudoers.d/
│   └── epikur                        # sudoers drop-in (copy to /etc/sudoers.d/)
├── .gitignore
├── LICENSE
└── README.md
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
