# Deployment Guide — Scholar Tracker

## Local / Development

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000

---

## Production (Linux VPS / Ubuntu)

### 1. Install system packages

```bash
sudo apt update
sudo apt install python3-pip python3-venv nginx -y
```

### 2. Clone / copy the app

```bash
mkdir -p /var/www/scholar_tracker
cp -r . /var/www/scholar_tracker/
cd /var/www/scholar_tracker
```

### 3. Set up virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install gunicorn           # production WSGI server
```

### 4. Set environment variable (SECRET_KEY)

```bash
cp .env.example .env
# Edit .env and set a long random SECRET_KEY:
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Load `.env` in your shell or set it in the systemd unit below.

### 5. Create a systemd service

```ini
# /etc/systemd/system/scholar_tracker.service
[Unit]
Description=Scholar Tracker Flask App
After=network.target

[Service]
User=www-data
WorkingDirectory=/var/www/scholar_tracker
Environment="SECRET_KEY=REPLACE_WITH_YOUR_KEY"
ExecStart=/var/www/scholar_tracker/venv/bin/gunicorn -w 4 -b 127.0.0.1:8000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable scholar_tracker
sudo systemctl start scholar_tracker
```

### 6. Configure Nginx as reverse proxy

```nginx
# /etc/nginx/sites-available/scholar_tracker
server {
    listen 80;
    server_name your-domain.com;

    client_max_body_size 20M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /uploads/ {
        # Serve uploads directly via Nginx for performance
        alias /var/www/scholar_tracker/uploads/;
        internal;  # only accessible via Flask's send_from_directory
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/scholar_tracker /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 7. Add HTTPS with Certbot (recommended)

```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d your-domain.com
```

---

## Demo Credentials (first run)

| Role    | Email               | Password  |
|---------|---------------------|-----------|
| Admin   | admin@scholar.edu   | admin123  |

> **Important:** Change all demo passwords before going live.

---

## Backup

The entire data is in one SQLite file:

```bash
cp /var/www/scholar_tracker/scholar_tracker.db /backups/scholar_$(date +%Y%m%d).db
```

Set up a daily cron for automated backups.
