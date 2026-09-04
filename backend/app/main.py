"""FastAPI application entrypoint for AetherMap-OSINT."""

import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.engines import history_diff, orchestrate_recon
from app.schemas import ReconRequest, ReconResponse
from app.tls_assessment import assess_services_tls

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
logger = logging.getLogger("aethermap.main")
VERSION = "3.2.0"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing AetherMap-OSINT scanner %s", VERSION)
    yield
    logger.info("Shutting down AetherMap-OSINT scanner")


app = FastAPI(title="AetherMap-OSINT API", description="Authorized-use OSINT attack-surface mapping with bounded TCP/UDP/TLS assessment and NVD correlation.", version=VERSION, docs_url="/docs", redoc_url="/redoc", lifespan=lifespan)


def _configured_cors_origins() -> list[str]:
    configured = os.getenv("ALLOWED_ORIGINS", "")
    return [o.strip() for o in configured.split(",") if o.strip()] if configured.strip() else ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000", "http://127.0.0.1:3000"]


app.add_middleware(CORSMiddleware, allow_origins=_configured_cors_origins(), allow_credentials=False, allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["Content-Type", "Accept"])


@app.get("/", tags=["System"], summary="Root service health probe", response_model=Dict[str, Any])
async def root_health_check():
    return {"service": "AetherMap-OSINT", "status": "OPERATIONAL", "version": VERSION, "engines": {"crt_sh": "passive", "dns": "active-safe-public-only", "tcp_scanner": "bounded-real-connect", "udp_scanner": "bounded-probes", "tls": "protocol-cipher-certificate-assessment", "cve_correlator": "NVD-CPE"}}


@app.get("/api/health", tags=["System"])
async def health_check():
    return {"status": "ok", "version": VERSION}


@app.post("/api/recon", tags=["Reconnaissance"], summary="Run authorized passive discovery and bounded active scan", response_model=ReconResponse, status_code=status.HTTP_200_OK)
async def execute_recon(payload: ReconRequest):
    logger.info("Recon request for '%s' (%s, max_assets=%s)", payload.domain, "custom ports" if payload.ports else "common ports", payload.max_assets)
    try:
        response = await orchestrate_recon(payload.domain, ports=payload.ports, max_assets=payload.max_assets)
        response.services = await assess_services_tls(response.services)
        return response
    except Exception as exc:
        logger.exception("Reconnaissance failed for '%s'", payload.domain)
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Reconnaissance upstream failed. Check service logs for diagnostics.") from exc


@app.get("/api/recon/history/{domain}", tags=["Reconnaissance"], summary="Compare the two latest scans")
async def get_history(domain: str):
    try:
        normalized = ReconRequest(domain=domain).domain
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"domain": normalized, **history_diff(normalized)}


@app.get("/api/recon/sample", tags=["Reconnaissance"], response_model=ReconResponse)
async def get_sample_recon():
    response = await orchestrate_recon("example.com", demo_mode=True)
    response.services = await assess_services_tls(response.services)
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.exception("Unhandled exception processing '%s'", request.url)
    return JSONResponse(status_code=500, content={"error": "InternalServerError", "message": "An unexpected server fault occurred."})
