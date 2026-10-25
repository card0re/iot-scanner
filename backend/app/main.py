import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import devices, stats, scans, reports, proxy_browse, probe, terminal, exploited
from app.database import Base, engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

app = FastAPI(title="IoT Vulnerability Scanner", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(devices.router, prefix="/api")
app.include_router(stats.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(proxy_browse.router, prefix="/api")
app.include_router(probe.router, prefix="/api")
app.include_router(terminal.router, prefix="/api")
app.include_router(exploited.router, prefix="/api")


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    from app.config import settings
    from app.collector import proxy_pool
    proxy_pool.load()
    if settings.proxy_url:
        proxy_pool.add_proxies([settings.proxy_url])


@app.get("/api/health")
def health():
    return {"status": "ok"}
