# Warehouse-Blog

English | [简体中文](./README-zh_CN.md) | [繁體中文](./README-zh_TW.md)

A self-hosted repository blog system with profiles, project showcases, a message board, and friendly links, using a static frontend and a local C/SQLite backend.

This repository is a reusable self-hosted template for a split deployment:

- static frontend: any static host or CDN
- API backend: local C service exposed through your preferred proxy or tunnel
- data storage: local SQLite + exported JSON mirror + local avatar files

Each page includes a language switcher so visitors can move between the three versions.

## Security cleanup in this repository

This version has been sanitized for public release:

- removed project-specific tunnel UUIDs, hostnames, and local paths
- removed personal admin account data and replaced it with template values
- replaced public API domain examples with placeholders
- replaced example admin credentials with generic starter values that you should change immediately

## Upstream attribution

This repository is derived from the original project by `LinusTrevian`.
The upstream project and author are already credited in the site "About" pages and remain credited in this public release.

## Layout

- `web/` static frontend files
- `backend/` C backend (`libmicrohttpd` + `sqlite3` + `jansson` + `curl` + `openssl`)
- `data/warehouse-blog.sqlite3` local SQLite database
- `data/export/site-state.json` JSON mirror export
- `data/uploads/avatars/` local avatar files
- `tools/api_health_logger.py` helper logger / health checker
- `backend/deploy/cloudflared/config.api.example.yml` example tunnel config

## Fedora 43 dependencies

```bash
sudo dnf install -y gcc make pkgconf-pkg-config unzip curl ca-certificates   libmicrohttpd-devel sqlite-devel jansson-devel libcurl-devel openssl-devel python3
```

## Debian 13 dependencies

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config unzip curl ca-certificates   libmicrohttpd-dev libsqlite3-dev libjansson-dev libcurl4-openssl-dev libssl-dev python3
```

## Build

```bash
cd backend
make
cd ..
```

## Local backend run

```bash
cp ./backend/scripts/server.env.example ./backend/scripts/server.env
set -a
source ./backend/scripts/server.env
set +a
./backend/warehouse-blog-server
```

Open local test page:



## Frontend API configuration

The frontend uses the following API base resolution order:

1. `window.WAREHOUSE_API_BASE`
2. `data-api-base` on the root HTML element
3. same-origin for `localhost` / `IP`
4. fallback placeholder: `https://your-api-domain.example`

Before production deployment, replace the placeholder with your real API origin.

## Frontend Hosting

Upload the contents of `web/` to your static hosting provider of choice.

## Direct Nginx Deployment

This repository can also be served directly from the server without a tunnel.

Recommended topology:

- Public site: your public domain
- Local backend only: `http://127.0.0.1:8080`
- Shared data: the same SQLite database and upload directory in this repository

Run the deployment helper on the server:

```bash
bash ./deploy_nginx.sh --domain your-site.example
```

After DNS for your domain points to the server, enable HTTPS:

```bash
sudo certbot --nginx -d your-site.example
```

Or let the helper run certbot:

```bash
bash ./deploy_nginx.sh --domain your-site.example --certbot
```

For later updates on the server:

```bash
bash ./update_dual_sites.sh your-site.example
```

The local backend port is the internal address Nginx proxies to. The default is `127.0.0.1:8080`; visitors do not access this port directly.

## Local API Through Tunnel

1. Install `cloudflared`
2. `cloudflared tunnel login`
3. `cloudflared tunnel create your-blog-api`
4. Bind `your-api-domain.example` to that tunnel
5. Use the example config from `backend/deploy/cloudflared/config.api.example.yml`

Example:

```bash
cloudflared tunnel route dns your-blog-api your-api-domain.example
cloudflared --config ~/.cloudflared/config.yml tunnel run your-blog-api
```

## Cookie / CORS notes

- For local HTTP testing keep `WB_COOKIE_SECURE=0`
- For production HTTPS, change it to `WB_COOKIE_SECURE=1`
- Update `WB_ALLOWED_ORIGINS` so it only contains your real frontend origins
- Leave `WB_COOKIE_DOMAIN=''` unless you explicitly want to widen cookie scope

## Email Verification

Registration now requires a 6-digit email verification code. Configure SMTP before enabling public registration:

```bash
WB_SMTP_URL='smtps://smtp.example.com:465'
WB_SMTP_USERNAME='smtp-user'
WB_SMTP_PASSWORD='smtp-password'
WB_SMTP_FROM='no-reply@example.com'
WB_SMTP_FROM_NAME='Warehouse-Blog'
```

## Python Helper Logger

```bash
python3 ./tools/api_health_logger.py   --local http://127.0.0.1:8080/api/health   --public https://your-api-domain.example/api/health   --profile https://your-api-domain.example/api/site-profile?lang=en
```

The logger writes to `./logs/api-health.log` by default.
