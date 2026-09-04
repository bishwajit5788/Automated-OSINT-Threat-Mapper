"""FastAPI application entrypoint for AetherMap-OSINT."""

import logging
from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.engines import orchestrate_recon
from app.schemas import ReconRequest, ReconResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("aethermap.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing AetherMap-OSINT reconnaissance API")
    yield
    logger.info("Shutting down AetherMap-OSINT reconnaissance API")


app = FastAPI(
    title="AetherMap-OSINT API",
    description=(
        "Authorized-use OSINT attack-surface mapping API. "
        "Certificate Transparency and DNS collection are passive/low-impact; "
        "network intelligence is explicitly marked simulated unless a real provider is configured."
    ),
    version="1.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Do not combine '*' with credentials. Configure deployed frontend origins explicitly.
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
)


@app.get("/", tags=["System"], summary="Root service health probe", response_model=Dict[str, Any])
async def root_health_check():
    return {
        "service": "AetherMap-OSINT",
        "status": "OPERATIONAL",
        "version": "1.1.0",
        "engines": {
            "crt_sh": "passive",
            "dns": "active",
            "network_intel": "simulated",
            "cve_correlator": "offline-catalog",
        },
    }


@app.get("/api/health", tags=["System"], summary="Health endpoint")
async def health_check():
    return {"status": "ok"}


@app.post(
    "/api/recon",
    tags=["Reconnaissance"],
    summary="Execute authorized OSINT reconnaissance",
    response_model=ReconResponse,
    status_code=status.HTTP_200_OK,
)
async def execute_recon(payload: ReconRequest):
    domain = payload.domain
    logger.info("Received reconnaissance request for '%s'", domain)
    try:
        response = await orchestrate_recon(domain)
        logger.info(
            "Recon completed for '%s': %d subdomains, %d services, score=%d",
            domain,
            len(response.subdomains),
            len(response.services),
            response.threat_score,
        )
        return response
    except Exception as exc:
        logger.exception("Reconnaissance failed for '%s'", domain)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Reconnaissance upstream failed. Check service logs for diagnostics.",
        ) from exc


@app.get("/api/recon/sample", tags=["Reconnaissance"], response_model=ReconResponse)
async def get_sample_recon():
    """Return a clearly marked demo dossier; it must not be interpreted as live findings."""
    return await orchestrate_recon("example.com", demo_mode=True)


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.exception("Unhandled exception processing '%s'", request.url)
    return JSONResponse(
        status_code=500,
        content={"error": "InternalServerError", "message": "An unexpected server fault occurred."},
    )
