# Complete Production Deployment Guide: FastAPI with Gunicorn & Nginx

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Project Structure](#project-structure)
3. [FastAPI Application Setup](#fastapi-application-setup)
4. [Gunicorn Configuration](#gunicorn-configuration)
5. [SystemD Service Setup](#systemd-service-setup)
6. [Nginx Configuration](#nginx-configuration)
7. [SSL with Let's Encrypt](#ssl-with-lets-encrypt)
8. [Security Hardening](#security-hardening)
9. [Monitoring & Logging](#monitoring--logging)
10. [Deployment Script](#deployment-script)

---

## 1. Prerequisites

### System Requirements
- Ubuntu 20.04/22.04 LTS or Debian 11/12
- Python 3.9+
- Root or sudo privileges

### Initial Server Setup
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install essential packages
sudo apt install -y python3-pip python3-venv nginx curl ufw git

# Create deployment user (security best practice)
sudo adduser --system --group --no-create-home fastapi
```

### Firewall Configuration
```bash
# Enable UFW
sudo ufw --force enable

# Allow SSH, HTTP, HTTPS
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Check status
sudo ufw status verbose
```

---

## 2. Project Structure

```
/home/fastapi/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── api/
│   │   ├── __init__.py
│   │   ├── v1/
│   │   │   ├── __init__.py
│   │   │   ├── endpoints.py
│   │   │   └── models.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py        # Configuration management
│   │   └── security.py
│   └── dependencies.py
├── requirements.txt
├── .env                     # Environment variables (not in git)
├── gunicorn.conf.py
├── nginx/
│   └── fastapi_app.conf    # Nginx site config
├── logs/
│   ├── gunicorn_access.log
│   ├── gunicorn_error.log
│   └── app.log
├── scripts/
│   └── deploy.sh
└── systemd/
    └── fastapi.service
```

---

## 3. FastAPI Application Setup

### `requirements.txt`
```txt
fastapi==0.104.1
uvicorn[standard]==0.24.0
gunicorn==21.2.0
python-dotenv==1.0.0
pydantic-settings==2.1.0
pydantic==2.5.0
sqlalchemy==2.0.23
psycopg2-binary==2.9.9  # or asyncpg for async
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
email-validator==2.1.0
python-multipart==0.0.6
redis==5.0.1
celery==5.3.4  # if needed
```

### `app/core/config.py`
```python
from pydantic_settings import BaseSettings
from typing import Optional
import secrets

class Settings(BaseSettings):
    # API
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "FastAPI Application"
    
    # Security
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # CORS
    BACKEND_CORS_ORIGINS: list = ["*"]  # Configure properly in production
    
    # Database
    DATABASE_URL: Optional[str] = None
    
    # Redis
    REDIS_URL: Optional[str] = "redis://localhost:6379"
    
    # Environment
    ENVIRONMENT: str = "production"
    DEBUG: bool = False
    
    # Logging
    LOG_LEVEL: str = "INFO"
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
```

### `app/main.py`
```python
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
import time
import logging

from app.core.config import settings
from app.api.v1.api import api_router

# Configure logging
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# Middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)

if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"] if settings.DEBUG else ["your-domain.com", "www.your-domain.com"]
)

# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    
    # Log slow requests
    if process_time > 1.0:  # More than 1 second
        logger.warning(
            f"Slow request: {request.method} {request.url.path} "
            f"took {process_time:.3f}s"
        )
    
    return response

# Include routers
app.include_router(api_router, prefix=settings.API_V1_STR)

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": time.time()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )
```

---

## 4. Gunicorn Configuration

### `gunicorn.conf.py`
```python
import multiprocessing
import os

# Server socket
bind = "unix:/tmp/gunicorn_fastapi.sock"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 1000
timeout = 30
keepalive = 2

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190

# Debugging
reload = False  # Never use in production!
spew = False

# Logging
accesslog = "/home/fastapi/logs/gunicorn_access.log"
errorlog = "/home/fastapi/logs/gunicorn_error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = "fastapi_app"

# Server mechanics
daemon = False
pidfile = "/tmp/gunicorn_fastapi.pid"
umask = 0o002
tmp_upload_dir = "/tmp"

# Worker processes
preload_app = True  # Load application before forking workers
max_requests = 1000  # Restart workers after this many requests
max_requests_jitter = 50  # Random jitter to prevent all workers restarting simultaneously

# SSL (if not using nginx SSL termination)
# keyfile = "/path/to/key.pem"
# certfile = "/path/to/cert.pem"
```

---

## 5. SystemD Service Setup

### Create service file: `/etc/systemd/system/fastapi.service`
```ini
[Unit]
Description=FastAPI Application with Gunicorn
After=network.target
Requires=postgresql.service  # If using PostgreSQL
After=postgresql.service
Requires=redis-server.service  # If using Redis
After=redis-server.service

[Service]
User=fastapi
Group=fastapi
WorkingDirectory=/home/fastapi/app
Environment="PATH=/home/fastapi/venv/bin"
EnvironmentFile=/home/fastapi/.env

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/home/fastapi/logs /tmp
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
MemoryDenyWriteExecute=true

# Process management
ExecStart=/home/fastapi/venv/bin/gunicorn -c /home/fastapi/gunicorn.conf.py app.main:app
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID
Restart=always
RestartSec=3
KillSignal=SIGTERM
TimeoutStopSec=10

# Resource limits
LimitNOFILE=65535
LimitNPROC=512

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fastapi

[Install]
WantedBy=multi-user.target
```

### Service Management Commands
```bash
# Reload systemd daemon
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable fastapi.service

# Start service
sudo systemctl start fastapi.service

# Check status
sudo systemctl status fastapi.service

# View logs
sudo journalctl -u fastapi.service -f

# Restart service
sudo systemctl restart fastapi.service

# Stop service
sudo systemctl stop fastapi.service
```

---

## 6. Nginx Configuration

### Main Nginx config: `/etc/nginx/nginx.conf`
```nginx
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    multi_accept on;
    use epoll;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    # Size Limits
    client_max_body_size 10M;
    client_body_buffer_size 128k;
    
    # MIME Types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # SSL Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    
    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Gzip Settings
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        application/atom+xml
        application/javascript
        application/json
        application/ld+json
        application/manifest+json
        application/rss+xml
        application/vnd.geo+json
        application/vnd.ms-fontobject
        application/x-font-ttf
        application/x-web-app-manifest+json
        application/xhtml+xml
        application/xml
        font/opentype
        image/bmp
        image/svg+xml
        image/x-icon
        text/cache-manifest
        text/css
        text/plain
        text/vcard
        text/vnd.rim.location.xloc
        text/vtt
        text/x-component
        text/x-cross-domain-policy;
    
    # Virtual Host Configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
```

### Site Configuration: `/etc/nginx/sites-available/fastapi_app`
```nginx
upstream fastapi_backend {
    server unix:/tmp/gunicorn_fastapi.sock fail_timeout=0;
}

server {
    listen 80;
    server_name your-domain.com www.your-domain.com;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none';" always;
    
    # Root and index
    root /var/www/html;
    index index.html;
    
    # Gunicorn proxy
    location / {
        proxy_pass http://fastapi_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffering
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        proxy_busy_buffers_size 8k;
        
        # Cache
        proxy_cache off;
    }
    
    # Static files (if any)
    location /static/ {
        alias /home/fastapi/app/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
        
        # Security for static files
        add_header X-Content-Type-Options "nosniff";
        add_header X-Frame-Options "DENY";
    }
    
    # Media files (if any)
    location /media/ {
        alias /home/fastapi/app/media/;
        expires 6M;
        add_header Cache-Control "public";
    }
    
    # Deny access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Deny access to sensitive files
    location ~* \.(env|log|sh|sql|py|pyc)$ {
        deny all;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        proxy_pass http://fastapi_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://fastapi_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    # Error pages
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    
    location = /50x.html {
        root /usr/share/nginx/html;
    }
}
```

### Enable the Site
```bash
# Remove default site
sudo rm /etc/nginx/sites-enabled/default

# Enable your site
sudo ln -s /etc/nginx/sites-available/fastapi_app /etc/nginx/sites-enabled/

# Test Nginx configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx

# Check Nginx status
sudo systemctl status nginx
```

---

## 7. SSL with Let's Encrypt

```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# The certbot will automatically modify your nginx config
# Test automatic renewal
sudo certbot renew --dry-run

# Set up auto-renewal cron job (certbot usually does this automatically)
sudo crontab -l | { cat; echo "0 12 * * * /usr/bin/certbot renew --quiet"; } | sudo crontab -
```

### Updated Nginx SSL Configuration
Certbot will modify your config, but here's what it should look like:

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name your-domain.com www.your-domain.com;
    
    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    
    # Include SSL configuration
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    
    # HSTS (force SSL)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # ... rest of your configuration ...
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name your-domain.com www.your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

---

## 8. Security Hardening

### Application Security
```python
# In your main.py, add these additional middleware:

from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware

if not settings.DEBUG:
    app.add_middleware(HTTPSRedirectMiddleware)

# Add security headers middleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["your-domain.com", "www.your-domain.com"]
)
```

### OS-Level Security
```bash
# Harden SSH
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Configure fail2ban for SSH and Nginx
sudo apt install -y fail2ban
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Create nginx jail
sudo tee /etc/fail2ban/jail.d/nginx.conf << EOF
[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-botsearch]
enabled = true
filter = nginx-botsearch
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2
EOF

sudo systemctl restart fail2ban

# Automatic security updates
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

### File Permissions
```bash
# Set proper permissions
sudo chown -R fastapi:fastapi /home/fastapi
sudo chmod 750 /home/fastapi
sudo chmod 644 /home/fastapi/.env  # If exists
sudo chmod -R 750 /home/fastapi/app
sudo chmod -R 770 /home/fastapi/logs

# Set immutable flag on critical files
sudo chattr +i /home/fastapi/.env 2>/dev/null || true
```

---

## 9. Monitoring & Logging

### Log Rotation
Create `/etc/logrotate.d/fastapi`:
```bash
/home/fastapi/logs/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 640 fastapi fastapi
    sharedscripts
    postrotate
        systemctl reload fastapi.service > /dev/null 2>&1 || true
    endscript
}
```

### Application Monitoring
```bash
# Install monitoring tools
sudo apt install -y htop nmon net-tools

# Monitor application
sudo journalctl -u fastapi.service -f --since "10 minutes ago"

# Check socket connections
ss -tulpn | grep :443
ss -tulpn | grep :80
```

### Health Check Script
Create `/usr/local/bin/check_fastapi.sh`:
```bash
#!/bin/bash

HEALTH_URL="https://your-domain.com/health"
MAX_ATTEMPTS=3
ATTEMPT=1

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_URL)
    
    if [ "$RESPONSE" = "200" ]; then
        echo "Application is healthy"
        exit 0
    fi
    
    echo "Attempt $ATTEMPT failed with HTTP $RESPONSE"
    ATTEMPT=$((ATTEMPT + 1))
    sleep 5
done

echo "Application health check failed after $MAX_ATTEMPTS attempts"
exit 1
```

Make it executable:
```bash
sudo chmod +x /usr/local/bin/check_fastapi.sh
```

---

## 10. Deployment Script

### `scripts/deploy.sh`
```bash
#!/bin/bash

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting deployment...${NC}"

# Variables
APP_USER="fastapi"
APP_DIR="/home/$APP_USER"
VENV_DIR="$APP_DIR/venv"
APP_SOURCE_DIR="$APP_DIR/app"
LOG_DIR="$APP_DIR/logs"
BRANCH=${1:-main}
GIT_REPO="your-git-repo-url"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Function to log messages
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Function to handle errors
error_exit() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" >&2
    exit 1
}

# Create directory structure
setup_directories() {
    log "Setting up directories..."
    
    if ! id "$APP_USER" &>/dev/null; then
        useradd --system --group --no-create-home "$APP_USER" || error_exit "Failed to create user"
    fi
    
    mkdir -p "$APP_DIR" "$LOG_DIR" "$APP_SOURCE_DIR"
    chown -R "$APP_USER:$APP_USER" "$APP_DIR"
    chmod 750 "$APP_DIR"
}

# Clone or update repository
update_code() {
    log "Updating application code..."
    
    cd "$APP_DIR"
    
    if [ -d "$APP_SOURCE_DIR/.git" ]; then
        cd "$APP_SOURCE_DIR"
        sudo -u "$APP_USER" git fetch origin || error_exit "Git fetch failed"
        sudo -u "$APP_USER" git checkout "$BRANCH" || error_exit "Git checkout failed"
        sudo -u "$APP_USER" git pull origin "$BRANCH" || error_exit "Git pull failed"
    else
        sudo -u "$APP_USER" git clone "$GIT_REPO" "$APP_SOURCE_DIR" || error_exit "Git clone failed"
        cd "$APP_SOURCE_DIR"
        sudo -u "$APP_USER" git checkout "$BRANCH" || error_exit "Git checkout failed"
    fi
}

# Setup Python virtual environment
setup_venv() {
    log "Setting up Python virtual environment..."
    
    if [ ! -d "$VENV_DIR" ]; then
        sudo -u "$APP_USER" python3 -m venv "$VENV_DIR" || error_exit "Failed to create virtual environment"
    fi
    
    # Activate venv and install requirements
    sudo -u "$APP_USER" "$VENV_DIR/bin/pip" install --upgrade pip wheel setuptools || error_exit "Failed to upgrade pip"
    
    if [ -f "$APP_SOURCE_DIR/requirements.txt" ]; then
        sudo -u "$APP_USER" "$VENV_DIR/bin/pip" install -r "$APP_SOURCE_DIR/requirements.txt" || error_exit "Failed to install requirements"
    fi
}

# Setup environment file
setup_env() {
    log "Setting up environment variables..."
    
    if [ ! -f "$APP_DIR/.env" ]; then
        if [ -f "$APP_SOURCE_DIR/.env.example" ]; then
            sudo -u "$APP_USER" cp "$APP_SOURCE_DIR/.env.example" "$APP_DIR/.env"
            echo -e "${YELLOW}Please update $APP_DIR/.env with production values${NC}"
        else
            sudo -u "$APP_USER" touch "$APP_DIR/.env"
        fi
    fi
    
    chown "$APP_USER:$APP_USER" "$APP_DIR/.env"
    chmod 640 "$APP_DIR/.env"
}

# Run database migrations (if applicable)
run_migrations() {
    log "Running database migrations..."
    
    if [ -f "$APP_SOURCE_DIR/alembic.ini" ]; then
        cd "$APP_SOURCE_DIR"
        sudo -u "$APP_USER" "$VENV_DIR/bin/alembic" upgrade head || error_exit "Database migration failed"
    fi
}

# Collect static files (if applicable)
collect_static() {
    log "Collecting static files..."
    
    if [ -f "$APP_SOURCE_DIR/manage.py" ]; then
        cd "$APP_SOURCE_DIR"
        sudo -u "$APP_USER" "$VENV_DIR/bin/python" manage.py collectstatic --noinput || error_exit "Failed to collect static files"
    fi
}

# Restart services
restart_services() {
    log "Restarting services..."
    
    # Reload systemd daemon
    systemctl daemon-reload || error_exit "Failed to reload systemd"
    
    # Restart FastAPI service
    systemctl restart fastapi.service || error_exit "Failed to restart FastAPI service"
    
    # Reload Nginx
    systemctl reload nginx || error_exit "Failed to reload nginx"
    
    # Wait for service to start
    sleep 5
    
    # Check service status
    if ! systemctl is-active --quiet fastapi.service; then
        error_exit "FastAPI service failed to start"
    fi
}

# Health check
health_check() {
    log "Performing health check..."
    
    sleep 3  # Give service time to start
    
    if ! /usr/local/bin/check_fastapi.sh; then
        error_exit "Health check failed"
    fi
}

# Main deployment flow
main() {
    log "Starting deployment process..."
    
    setup_directories
    update_code
    setup_venv
    setup_env
    run_migrations
    collect_static
    restart_services
    health_check
    
    log "${GREEN}Deployment completed successfully!${NC}"
}

# Run main function
main "$@"
```

### Make it executable:
```bash
chmod +x scripts/deploy.sh
```

### Usage:
```bash
# Deploy with default branch (main)
sudo ./scripts/deploy.sh

# Deploy specific branch
sudo ./scripts/deploy.sh develop
```

---

## Final Verification Steps

1. **Test the application:**
```bash
curl -I https://your-domain.com/health
curl https://your-domain.com/api/v1/
```

2. **Check all services:**
```bash
sudo systemctl status fastapi.service
sudo systemctl status nginx
sudo systemctl status postgresql  # if using
sudo systemctl status redis-server  # if using
```

3. **Monitor logs:**
```bash
# Real-time monitoring
sudo journalctl -u fastapi.service -f
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

4. **Security scan:**
```bash
# Install security scanner
sudo apt install -y nmap

# Scan your own server (from another machine)
nmap -sV --script http-security-headers your-domain.com
```

---

## Maintenance Commands Cheatsheet

```bash
# View application logs
sudo journalctl -u fastapi.service -n 100
sudo tail -f /home/fastapi/logs/gunicorn_error.log

# Restart services
sudo systemctl restart fastapi.service
sudo systemctl reload nginx

# Backup database (example for PostgreSQL)
sudo -u postgres pg_dump database_name > backup_$(date +%Y%m%d).sql

# Update SSL certificates
sudo certbot renew

# Check disk space
df -h
du -sh /home/fastapi/logs/*

# Monitor processes
htop
sudo netstat -tulpn | grep :443
```

---

## Important Notes for Production

1. **Never store secrets in version control**
2. **Use environment variables for configuration**
3. **Regularly update dependencies** (`pip list --outdated`)
4. **Set up automated backups**
5. **Implement proper monitoring (Prometheus/Grafana recommended)**
6. **Use a CDN for static assets**
7. **Implement rate limiting per endpoint**
8. **Regular security audits**
9. **Keep OS and packages updated**
10. **Test your backups regularly**

This guide provides a comprehensive production deployment setup. Adjust configurations based on your specific application requirements, traffic patterns, and security needs.
