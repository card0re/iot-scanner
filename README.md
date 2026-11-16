# IoT Vulnerability Scanner

Scans the internet for exposed IoT devices, figures out what they are, checks how vulnerable they might be, and tries to prove it by testing default credentials. Everything runs through a self-maintaining proxy pool so you're not hitting targets from your own IP.

I built this mostly as a research tool. Works out of the box with zero API keys — it'll use Shodan's free InternetDB endpoint to look up devices. Throw in a paid Shodan or Censys key and it gets a lot more capable.

**Fair warning:** don't point this at anything you don't own or have written permission to test.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)
![React](https://img.shields.io/badge/React-18-61dafb)
![License](https://img.shields.io/badge/License-MIT-yellow)

## How it works

The scanner samples random IPs from known address ranges (currently Iran and Russia, easy to extend), hits Shodan InternetDB for each one, and pulls back whatever port/service info is available. With a paid key it also runs targeted search queries for webcams, routers with default passwords, and similar stuff. There's Censys support too — it queries for Telnet, RTSP, MQTT, UPnP services and specific vendors like Hikvision and Dahua.

Once devices are collected, a rule-based classifier sorts them into categories — cameras, routers, DVRs, NAS devices, printers, SCADA/ICS, smart home gear, and industrial equipment. It looks at banners, open ports, CPE strings, and known product signatures.

Then comes the fun part. The exploit engine builds a per-device attack strategy based on what ports are open, what CVEs were found, and what product it thinks it's looking at. It goes through SSH and Telnet brute-force with vendor-specific default creds (Hikvision, Dahua, MikroTik, TP-Link, D-Link, QNAP, Synology, Siemens — the list is pretty long), HTTP Basic auth, and even form-based login attempts. If it gets in, it runs proof commands (`id`, `whoami`, `uname -a`) and records the evidence.

All the exploit traffic goes through a proxy pool that the system maintains on its own — it scrapes free SOCKS4/5 and HTTP proxies from multiple sources, verifies them in parallel, picks country-appropriate ones for each target, and persists everything across restarts.

## Features at a glance

- **Device discovery** via Shodan InternetDB (free) + Shodan Search (paid) + Censys
- **Direct port scanner** for when you want to skip the APIs entirely
- **Auto-classification** of device types from banners, ports, and product fingerprints
- **CVE mapping** through NVD lookups with composite vulnerability scoring
- **Automated exploit engine** — SSH, Telnet, HTTP brute-force with smart per-device strategy
- **Huge default credential database** organized by device type and vendor
- **Self-healing proxy pool** with auto-scraping, parallel verification, and country-aware routing
- **In-browser SSH/Telnet terminal** (xterm.js over WebSocket) for interacting with compromised devices
- **Reverse proxy browser** — view a device's web panel through the backend without a direct connection
- **HTML vulnerability reports** per manufacturer, ready for responsible disclosure
- **React dashboard** with live stats, charts, device table with filters, scan controls, and exploit tracking

## Architecture

```
React + Vite (frontend)
   |
   v
FastAPI + SQLAlchemy (backend)
   |
   +-- Collectors (Shodan, Censys, Direct Scanner)
   +-- ML Pipeline (Classifier, Vuln Scorer, CVE Mapper)
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

# set up your env — API keys are optional, it works without them
cp .env.example .env

# spin everything up
docker compose up --build
```

That's it. Dashboard lives at `http://localhost:3000`, API at `http://localhost:8000`, Swagger docs at `http://localhost:8000/docs`.

## Environment variables

| Variable | What it does | Needed? |
|---|---|---|
| `DATABASE_URL` | Postgres connection string | Has a default |
| `REDIS_URL` | Redis connection string | Has a default |
| `SHODAN_API_KEY` | Unlocks Shodan search queries (way more results) | Optional |
| `CENSYS_API_ID` | Censys API credentials | Optional |
| `CENSYS_API_SECRET` | Censys API credentials | Optional |
| `GCP_PROJECT_ID` | Only needed if you're deploying to Cloud Run | Optional |
| `GCP_REGION` | GCP region, defaults to europe-west1 | Optional |

## Stack

**Backend** — Python 3.12, FastAPI, SQLAlchemy, Alembic, asyncssh, telnetlib3, httpx, Shodan & Censys SDKs, Jinja2

**Frontend** — React 18, Vite, Recharts, xterm.js, Axios

**Infrastructure** — PostgreSQL, Redis, Docker Compose, nginx. Optional Cloud Run deployment via included `deploy.sh`.

## Project layout

```
backend/
  app/
    api/          # REST + WebSocket endpoints
    collector/    # Shodan, Censys, direct scanner, proxy scraper & pool
    ml/           # Device classifier, vuln scorer, CVE mapper
    models/       # SQLAlchemy models
    services/     # Exploit engine + strategy builder
    reports/      # HTML report generator
    config.py     # Env-based settings
    wordlists.py  # Default credential lists (organized by device type)

frontend/
  src/
    components/   # ScanPanel, DeviceTable, Charts, WebTerminal, etc.
    api/          # Axios-based API client
```

## Deploying to the cloud

There's a `deploy.sh` that handles Google Cloud Run deployments end-to-end — enables APIs, builds both containers with Cloud Build, deploys the backend first, grabs its URL, rebuilds the frontend with the correct API endpoint baked in, and deploys that too. Just make sure you have `gcloud` set up and the relevant env vars exported.

## Legal

This is a security research tool. Using it against systems without explicit authorization is illegal pretty much everywhere. I take no responsibility for how anyone chooses to use this. Get permission first — in writing, ideally.
