# WAF – Simple Web Application Firewall (Demo)

This is a small, self-contained demo that showcases a reverse-proxy WAF plus an admin dashboard. It’s designed for learning and portfolio review, not production use.

> Açıklama (TR): Bu proje, BOTAŞ’taki siber güvenlik staj sürecimde, siber güvenlik ekibinin yönlendirmesiyle eğitim ve portföy amaçlı hazırlanmıştır. Gerçek üretim ortamlarında BOTAŞ tarafından kullanılmamaktadır. WAF mantığını uçtan uca anlamak ve kendimi kanıtlamak amacıyla, sınırlı ve anlaşılır bir kapsamda geliştirdim.

> Disclaimer (EN): Built during my cybersecurity internship at BOTAŞ under team guidance as a learning/portfolio project. Not used by BOTAŞ in production. I built it to understand WAF concepts end-to-end and to demonstrate capability.

What’s inside:
- Reverse-proxy WAF (Python, aiohttp) that inspects requests, bans/whitelists IPs, and proxies traffic
- Admin API (FastAPI) to manage sites, IPs, patterns, logs, and VirusTotal (VT) cache
- Admin Web (React + MUI) to control everything visually

---

## Highlights
- Request inspection across path, query, headers, and body
- Pattern-based blocking (XSS / SQL / CUSTOM) sourced from DB (simple substring matching)
- VirusTotal IP reputation checks with a Redis-backed daily cache
- Ban/whitelist stored in Redis (`banned_ip:` / `clean_ip:`)
- Request/response logging to MongoDB (blocked reason included)
- Admin API + Admin Web + Docker Compose

---

## System Architecture (at a glance)
```
[ Client ] → [ WAF (aiohttp) ] → [ Protected Site Frontend/Backend ]
                      |
                      |-- Redis (ban/whitelist + VT cache)
                      |-- MongoDB (request/response logs)
                      |-- Postgres (sites + malicious patterns)

[ Admin Web (React) ] → [ Admin API (FastAPI) ] → Postgres / Redis / MongoDB
```

- WAF process dynamically spins up listeners per configured site/port and transparently proxies HTTP/WS traffic.
- Each incoming request is checked in sequence (whitelist → banned → VirusTotal → patterns). First “hit” short-circuits and blocks.
- All requests/responses (and blocks) are logged to MongoDB for auditing and UI.

---

## Repository Structure (short)
```
WAF/
├─ api/                    # Admin API (FastAPI)
│  └─ app/
│     ├─ core/             # settings, security, dependencies
│     ├─ database.py       # async engine/session provider
│     ├─ models.py         # SQLAlchemy models (User, Site, MaliciousPattern)
│     ├─ routers/          # auth, sites, ips, patterns, system, logs
│     └─ main.py           # FastAPI app, CORS, lifespan
│
├─ waf/                    # WAF runtime (aiohttp)
│  ├─ app/server.py        # WAFManager (listeners, proxy, orchestration)
│  ├─ checks/
│  │  ├─ security_engine.py            # Chain orchestration for request checks
│  │  └─ patterns/pattern_store.py     # Pattern cache + analysis
│  ├─ adapters/virustotal/
│  │  ├─ sync_client.py                # VirusTotal HTTP client (requests)
│  │  ├─ cache.py                      # Redis-backed daily cache
│  │  └─ cached_client.py              # Adapter combining client + cache
│  ├─ integration/
│  │  ├─ db/{connection.py,repository.py}        # Engine + repositories
│  │  └─ logging/request_logger.py               # MongoDB logger
│  ├─ ip/{local.py,banlist.py,ban_actions.py,info_store.py}
│  ├─ Dockerfile
│  └─ requirements.txt
│
├─ web/                    # Admin Web (React + Vite + MUI)
│  ├─ src/
│  │  ├─ api/              # API clients (fetch wrapper)
│  │  ├─ components/       # IP Mgmt, Pattern Mgmt, Log Viewer, VT Stats, etc.
│  │  ├─ context/          # Auth context
│  │  └─ App.tsx           # Routes & layout
│  └─ Dockerfile
│
├─ docker-compose.yml      # Full local stack (Postgres, Redis, MongoDB, API, WAF, Web)
└─ init-db.sql, hosts_entries.txt, etc.
```

---

## Data Model (Core)
- `Site`: port + host mapping with frontend/backend URLs and check toggles (`xss_enabled`, `sql_enabled`, `vt_enabled`)
- `MaliciousPattern`: `pattern`, `type` (`XSS`/`SQL`/`CUSTOM`), `description`, timestamps
- `User`: admin users (for Admin Web access) — managed by the API; seeded via migrations

Models live in `api/app/models.py` and are consumed by the WAF runtime.

---

## How it works
- Entrypoint: `python -m waf.app.server`
- Orchestration: `WAFManager` manages per-port listeners, proxy, and logging
- Checks: `waf/checks/security_engine.py`
  1) Whitelist (Redis `clean_ip:<ip>`)
  2) Banned list (Redis `banned_ip:<ip>`)
  3) VirusTotal (optional per site) via `CachedVirusTotalClient`
  4) Pattern scan across body, path, query and headers
- Ban action: `waf/ip/ban_actions.py` (writes `banned_ip:<ip>` with TTL)
- Pattern cache: `waf/checks/patterns/pattern_store.py` (TTL fetch from Postgres)
- Logging: `waf/integration/logging/request_logger.py` stores request/response documents + block reasons in MongoDB

Headers added on proxied responses: `X-WAF-Protected: true`, `X-WAF-Site: <name>`

---

## Admin API (FastAPI)
- App: `api/app/main.py` with CORS, lifespan, and routers
- Routers: `auth`, `sites`, `ips`, `patterns`, `system`, `logs`
  - `auth`: login → JWT
  - `ips`: list/ban/unban, whitelist/unwhitelist
  - `patterns`: CRUD + bulk upload (text file)
  - `system`: VT cache stats and cleanup
  - `logs`: query requests, responses, blocked entries, statistics

---

## Admin Web (React + MUI)
- Protected routes using simple token presence (stored in localStorage)
- Key views: Sites, IP Management, Patterns, Logs, VirusTotal Stats
- Uses `src/api/client.ts` as a lightweight fetch wrapper that injects JWT and handles 401/403 redirects

---

## Quickstart (Docker Compose)
Prerequisites: Docker + Docker Compose

1) Create `.env` at project root (minimum):
```
JWT_SECRET=change-me
VIRUSTOTAL_API_KEY=
```
2) Start the stack:
```
docker compose up --build
```
3) Open:
- Admin Web: `http://localhost:5173`
- Admin API: `http://localhost:8002`
- WAF (proxy): `http://localhost:80`

---

## Configuration (common)
Environment (most common):
- `DATABASE_URL` (Postgres) — used by both WAF and API
- `REDIS_URL` — ban/whitelist + VT cache
- `MONGODB_URL` — request/response logs for WAF and Logs API
- `VIRUSTOTAL_API_KEY` — optional (enables VT checks per site)
- `DEBUG`, `POLL_INTERVAL` — WAF runtime behavior

Site-level toggles (in DB):
- `xss_enabled`, `sql_enabled`, `vt_enabled`

---

## Typical Request Flow
1) Client hits WAF listener (port resolved from `Site.port`)
2) Hostname (exact or wildcard) determines the `Site` configuration
3) Security checks run in order; on hit → `403` block page with reason
4) Otherwise proxy proceeds to `frontend_url` or `backend_url` (if path starts with `/api/`)
5) Request and response are logged to MongoDB with timing

---

## Adding Protected Sites using Docker DNS
The WAF can reach backend apps by Docker-internal DNS if both are on the same Docker network.

- Current setup (see `docker-compose.yml`): the WAF service joins these networks:
  - `waf-core-net` (core infra)
  - `juiceshop-net` (example vulnerable app network)
  - `hr-system-net` (my own HR system app network)

- Example 1 — Internal container (Juice Shop):
  - Run the app on a shared network with an alias (Docker Compose excerpt):
    ```yaml
    services:
      juice_shop_app:
        image: bkimminich/juice-shop
        environment:
          - PORT=80
        networks:
          juiceshop-net:
            aliases: ["juiceshop-internal"]
    networks:
      juiceshop-net:
        external: true
    ```
  - Ensure the WAF service is also attached to `juiceshop-net` (already is in compose).
  - In Admin Web → Sites, set `frontend_url`/`backend_url` to:
    - `http://juiceshop-internal/` (Docker DNS resolves this alias).

- Example 2 — HR System (my own app):
  - Run your HR system containers on `hr-system-net` and assign service aliases (e.g., `hr-frontend`, `hr-backend`).
  - Ensure the WAF service is attached to `hr-system-net` (already present).
  - In Admin Web → Sites, point URLs to `http://hr-frontend/` and/or `http://hr-backend/`.

- Example 3 — External site (GitHub):
  - You can point a site to any public URL (e.g., `https://github.com/`). No shared network needed.

- Pretty hostnames for browser access (optional):
  - Map hostnames like `juiceshop.local`, `github.local` to `127.0.0.1` in `/etc/hosts`, then add matching `host` values in “Sites.”

Tips
- To add another internal service, create/attach a network shared with the WAF and use a stable alias; point the site URLs to `http://<alias>/`.
- If a network doesn’t exist yet: `docker network create <network-name>` and reference it in compose.

## Troubleshooting
- WAF container failing to import `waf.*`: ensure Dockerfile copies `./waf/` to `/app/waf/` and entrypoint uses `python -m waf.app.server`
- VT disabled or rate-limited: VT checks are optional per-site and errors are non-fatal
- Logs empty: confirm `MONGODB_URL` is reachable and collections are created at startup by the WAF logger

