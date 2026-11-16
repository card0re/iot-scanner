# IoT Vulnerability Scanner

Finds IoT devices exposed on the public internet, identifies what they are, maps their CVEs, and tests whether they still have default credentials. Covers SSH, Telnet, and HTTP login pages. All traffic routes through an auto-maintained proxy pool, so nothing hits the target from your real IP.

Works with zero API keys out of the box. Without a Shodan key it falls back to the free InternetDB endpoint, which returns open ports and known CVEs for any IP you ask about. Add a paid Shodan or Censys key and it switches to full search queries with way more coverage.

Don't use this on anything you don't own or have written permission to test.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)
![React](https://img.shields.io/badge/React-18-61dafb)
![License](https://img.shields.io/badge/License-MIT-yellow)

## How it works

### Discovery

The scanner picks random IPs from hardcoded CIDR ranges (Iran and Russia right now, about 400 ranges between them). For each IP it queries Shodan's InternetDB, a free API that returns open ports, hostnames, CPEs, and known CVEs without needing an API key. The sampling is weighted so larger subnets get proportionally more hits, and IPs from previous scans are skipped to avoid duplicates.

With a paid Shodan key, the scanner also runs direct search queries: `webcam country:IR`, `Router country:RU`, `"default password" country:IR`, and so on. These return richer data (banners, geolocation, ASN, full service fingerprints) for up to a few hundred devices per query.

Censys works similarly. It queries for specific service types (Telnet, RTSP, MQTT, UPnP) and specific vendors (Hikvision, Dahua, MikroTik) filtered by country. The results come back with service banners, software versions, and autonomous system info.

There's also a direct port scanner that skips both APIs entirely. It takes an IP range, scans common IoT ports (23, 80, 443, 554, 1883, 5900, 8080, 8443, 502, 161, and others), grabs banners, and feeds everything into the same pipeline.

All three sources normalize their data into the same format before it hits the database.

### Classification

Once a device is in the database, a rule-based classifier tries to figure out what it is. It checks the banner text, open ports, CPE strings, manufacturer field, and firmware version against keyword lists for each device type:

- Cameras: hikvision, dahua, rtsp, onvif, axis, ipcam, webcam
- Routers: mikrotik, routeros, openwrt, dd-wrt, netgear, tp-link
- DVRs/NVRs: dvr, nvr, recorder, cctv
- NAS: synology, qnap, wd my cloud, freenas
- Printers: laserjet, epson, brother, cups
- SCADA/ICS: modbus, plc, siemens, schneider, hmi
- Smart home: home assistant, tuya, zigbee, mqtt, tasmota
- Industrial: bacnet, dnp3, profinet

If keywords don't match, it falls back to port heuristics: port 554 likely means a camera, port 502 likely means SCADA, port 9100 likely means a printer. Each classification comes with a confidence score.

### Vulnerability scoring

The scanner maps CPE strings to CVEs through NVD lookups. Each device gets a composite vulnerability score based on the number of CVEs, their CVSS scores, and how many of them mention things like "default credentials", "authentication bypass", or "remote code execution". Devices with auth-bypass CVEs get prioritized for exploit testing.

### Exploit engine

The exploit engine builds a per-device attack plan. It looks at what ports are open, what CVEs were found, and what product was detected, then produces a ranked list of attack vectors sorted by likelihood of success.

For SSH (ports 22, 2222, 2022) and Telnet (ports 23, 2323), it runs brute-force with vendor-specific default credential lists. The wordlists cover:

- Hikvision: admin/admin, admin/12345, admin/Hikvision, admin/abcd1234
- Dahua: admin/admin, admin/admin123, admin/dahua
- MikroTik: admin/(empty)
- TP-Link, D-Link, Netgear, Asus, Linksys, Cisco, ZTE, Huawei, Ubiquiti
- QNAP, Synology, Western Digital (NAS devices)
- Siemens, Schneider Electric, ABB, GE, Honeywell (SCADA/ICS)
- HP, Epson, Brother, Xerox, Ricoh (printers)

Around 300 unique username/password pairs total, organized by device type. The engine tries type-specific creds first, then falls back to universal defaults like root/root, admin/admin, admin/password.

For HTTP (ports 80, 443, 8080, 8443, and about a dozen others), it tries three things. First, unauthenticated access to known admin paths: if a device has an auth-bypass CVE, it checks whether `/`, `/admin`, `/login`, `/cgi-bin/login.cgi` and product-specific paths (like `/ISAPI/Security/userCheck` for Hikvision or `/webfig/` for MikroTik) are reachable without credentials. Second, HTTP Basic auth with the same credential lists. Third, form-based POST login, trying common field name combinations like username/password, user/pass, login/password.

When a brute-force attempt succeeds over SSH or Telnet, the engine runs `id`, `whoami`, and `uname -a` on the device and records the output as proof. It also detects the access level: root if the output contains `uid=0`, regular user otherwise.

The whole thing is async with configurable concurrency (default 8 simultaneous attempts per device) and a 45-second timeout per device so one slow target doesn't block the queue.

### Proxy pool

The proxy system runs as a background daemon. Every 5 minutes it scrapes free proxy lists from about 20 sources, pulling SOCKS4, SOCKS5, and HTTP proxies. New proxies are verified in parallel (up to 3000 per cycle) by testing actual connectivity through each one.

Each proxy is tagged with its country and protocol support. When the exploit engine needs to reach a device in Iran, it picks a proxy geolocated near Iran. If a proxy fails during an exploit attempt, it gets marked down; after enough failures it gets dropped from the pool. The whole pool persists to disk so it survives backend restarts.

### Web terminal

The dashboard includes a browser-based SSH and Telnet terminal. It uses xterm.js on the frontend connected to the backend over WebSocket. You pick a device, enter credentials (or use the suggested defaults for that device type), and get a live shell session in the browser. Supports terminal resizing and xterm-256color.

### Reverse proxy

There's a reverse proxy endpoint that lets you view a device's web interface through the backend. The frontend sends the target URL, the backend fetches it (optionally through a proxy from the pool), rewrites internal links and asset paths so they route back through the backend, and returns the page. Useful for checking camera web panels or router admin pages without connecting to them directly.

### Reports

The report generator produces HTML vulnerability reports grouped by manufacturer. Each report lists affected devices with their IPs, ports, firmware versions, vulnerability scores, and associated CVEs sorted by CVSS score. The reports are meant for responsible disclosure to manufacturers.

## Architecture

```
React + Vite (frontend)
   |
   v
FastAPI + SQLAlchemy (backend)
   |
   +-- Collectors (Shodan, Censys, Direct Scanner)
   +-- Classifier + Vuln Scorer + CVE Mapper
   +-- Exploit Engine (SSH, Telnet, HTTP brute)
   +-- Proxy Pool (auto-scraped, country-aware)
   +-- Report Generator
   |
   v
PostgreSQL + Redis
```

## Getting started

```bash
git clone https://github.com/card0re/iot-scanner.git
cd iot-scanner

cp .env.example .env
# add SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET if you have them
# works without any of them

docker compose up --build
```

Dashboard: `http://localhost:3000`
API: `http://localhost:8000`
Swagger docs: `http://localhost:8000/docs`

## Environment variables

All settings live in `.env` or system environment variables.

| Variable | Description | Required |
|---|---|---|
| `DATABASE_URL` | Postgres connection string | Has a default |
| `REDIS_URL` | Redis connection string | Has a default |
| `SHODAN_API_KEY` | Enables Shodan search queries (much more coverage) | No |
| `CENSYS_API_ID` | Censys credentials | No |
| `CENSYS_API_SECRET` | Censys credentials | No |
| `GCP_PROJECT_ID` | For Cloud Run deployment | No |
| `GCP_REGION` | GCP region, defaults to europe-west1 | No |

## Stack

Backend: Python 3.12, FastAPI, SQLAlchemy, Alembic, asyncssh, telnetlib3, httpx, Shodan SDK, Censys SDK, Jinja2

Frontend: React 18, Vite, Recharts, xterm.js, Axios

Infrastructure: PostgreSQL, Redis, Docker Compose, nginx. Optional Cloud Run deployment through included `deploy.sh`.

## Project layout

```
backend/
  app/
    api/          # REST + WebSocket endpoints
    collector/    # Shodan, Censys, direct scanner, proxy scraper and pool
    ml/           # Device classifier, vuln scorer, CVE mapper
    models/       # SQLAlchemy models
    services/     # Exploit engine + strategy builder
    reports/      # HTML report generator
    config.py     # Env-based settings
    wordlists.py  # ~300 default credentials organized by device type

frontend/
  src/
    components/   # ScanPanel, DeviceTable, Charts, WebTerminal, etc.
    api/          # Axios API client
```

## Cloud deployment

The `deploy.sh` script handles Google Cloud Run from start to finish. It enables the required GCP APIs, builds both containers with Cloud Build, deploys the backend, grabs its URL, rebuilds the frontend with the correct API endpoint, and deploys that too. Requires `gcloud` configured and the env vars exported.

## Legal

This is a security research tool. Scanning or exploiting devices without explicit permission from the owner is illegal in most countries. I am not responsible for how anyone uses this. Get written authorization before testing anything you don't own.
