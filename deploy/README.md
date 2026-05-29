# Deploying Keybox on Ubuntu (auto-start + HTTPS via Caddy)

This sets up the Keybox web UI as a systemd service that starts on boot, with
[Caddy](https://caddyserver.com/) terminating TLS in front of it so traffic on
your LAN is encrypted.

```
Browser  --HTTPS-->  Caddy (:443)  --HTTP-->  gunicorn (127.0.0.1:8000)  -->  webapp:app
```

## Why this shape

- **gunicorn `--workers 1 --threads N`** — the app holds the unlocked AES key in
  process memory (per session), so it must be a single process. Threads give
  concurrency without splitting that memory across workers.
- **Fixed `KEYBOX_SECRET`** — otherwise every restart/reboot generates a new
  Flask secret and logs everyone out.
- **`KEYBOX_DB` set explicitly** — the default DB path reads `$HOME`/`$USER`,
  which systemd may not provide.
- **`KEYBOX_BEHIND_PROXY=1`** — makes Flask trust Caddy's `X-Forwarded-Proto`
  and mark the session cookie `Secure`.
- **gunicorn binds to `127.0.0.1`** — only Caddy is exposed to the LAN.

## 1. Code, user, data dir, venv

```bash
sudo mkdir -p /opt/pykeybox && sudo chown $USER /opt/pykeybox
git clone <your-repo-url> /opt/pykeybox        # or scp/rsync the files
cd /opt/pykeybox

sudo useradd --system --no-create-home --shell /usr/sbin/nologin keybox
sudo mkdir -p /var/lib/keybox
sudo chown keybox:keybox /var/lib/keybox && sudo chmod 700 /var/lib/keybox

sudo apt update && sudo apt install -y python3-venv
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt gunicorn
sudo chown -R keybox:keybox /opt/pykeybox
```

## 2. The systemd service

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"   # copy this
sudo cp deploy/keybox.service /etc/systemd/system/keybox.service
sudo nano /etc/systemd/system/keybox.service                # paste into KEYBOX_SECRET

sudo systemctl daemon-reload
sudo systemctl enable --now keybox.service
sudo systemctl status keybox.service
```

## 3. Caddy

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy
```

Edit `deploy/Caddyfile` — set the site address to the hostname (or IP) you'll
use, e.g. `keybox.home` or `192.168.1.50`. Then install it:

```bash
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
sudo systemctl restart caddy
sudo systemctl enable caddy        # Caddy's package already enables this by default
```

## 4. Firewall (if ufw is enabled)

```bash
sudo ufw allow from 192.168.0.0/16 to any port 443 proto tcp   # restrict to LAN
```

## 5. Trust Caddy's internal CA (to avoid browser warnings)

On the server, the CA is trusted automatically. For *other* devices, export the
root and install it on each one:

```bash
sudo caddy trust                                   # trust on the server itself
# Root cert to distribute to phones/laptops:
# /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt
```

Install that `root.crt` as a trusted root CA on each client (macOS Keychain,
Windows cert store, iOS/Android profile, Firefox's own store). Until then the
browser will show a certificate warning you can bypass.

If you used a hostname like `keybox.home`, also make sure each client resolves
it — add it to your router's DNS or to the client's `hosts` file pointing at the
server's LAN IP.

## Access & updates

- Visit `https://keybox.home` (or your chosen address). First load prompts you
  to set the master password.
- Update: `git pull` in `/opt/pykeybox`, then
  `sudo systemctl restart keybox.service`.

## Note on transport security

The SQLite database is AES-encrypted at rest. With this setup, LAN traffic is
also encrypted via TLS. If you ever revert to plain gunicorn on `0.0.0.0`
without Caddy, your master password would travel the LAN in cleartext — don't.
