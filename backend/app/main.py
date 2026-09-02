"""FastAPI Application Entrypoint for AetherMap-OSINT Threat Intelligence Platform."""

import logging
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.engines import orchestrate_recon
from app.schemas import ReconRequest, ReconResponse

# Configure structured application logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("aethermap.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown routines."""
    logger.info("Initializing AetherMap-OSINT Threat Reconnaissance Engine...")
    yield
    logger.info("Gracefully shutting down AetherMap-OSINT engines.")


app = FastAPI(
    title="AetherMap-OSINT API",
    description=(
        "Enterprise-grade Automated OSINT Threat Mapper & Attack Surface Visualizer API. "
        "Provides asynchronous Certificate Transparency exploration, Shodan network layer profiling, "
        "and CVE correlation feeds."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS Configuration: Enforce explicit origins for frontend React/Vite development server
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get(
    "/",
    tags=["System"],
    summary="Root Service Health Probe",
    response_model=Dict[str, Any]
)
async def root_health_check():
    """System health check and operational status endpoint."""
    return {
        "service": "AetherMap-OSINT",
        "status": "OPERATIONAL",
        "version": "1.0.0",
        "engines": {
            "crt_sh": "active",
            "shodan_simulator": "active",
            "cve_correlator": "active"
        }
    }


@app.post(
    "/api/recon",
    tags=["Reconnaissance"],
    summary="Execute Asynchronous OSINT Threat Reconnaissance",
    response_model=ReconResponse,
    status_code=status.HTTP_200_OK
)
async def execute_recon(payload: ReconRequest):
    """Execute asynchronous multi-source attack surface discovery on target domain.

    Orchestrates Certificate Transparency queries, asynchronous DNS resolution,
    and Shodan network layer CVE correlation.
    """
    domain = payload.domain
    logger.info("Received OSINT reconnaissance request for target domain: '%s'", domain)

    try:
        response: ReconResponse = await orchestrate_recon(domain)
        logger.info(
            "Reconnaissance completed for '%s': Found %d subdomains, %d services, Threat Score: %d (%s)",
            domain,
            len(response.subdomains),
            len(response.services),
            response.threat_score,
            response.risk_level,
        )
        return response
    except Exception as exc:
        logger.error("Failed to complete OSINT scan for '%s': %s", domain, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Reconnaissance engine encountered an error: {str(exc)}"
        )


@app.get(
    "/api/recon/sample",
    tags=["Reconnaissance"],
    summary="Get Sample Reconnaissance Dossier",
    response_model=ReconResponse
)
async def get_sample_recon():
    """Return a pre-generated sample reconnaissance dossier for immediate testing and UI preview."""
    sample_domain = "tesla.com"
    return await orchestrate_recon(sample_domain)


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global unhandled exception interceptor."""
    logger.error("Unhandled exception processing request '%s': %s", request.url, exc)
    return JSONResponse(
        status_code=500,
        content={"error": "InternalServerError", "message": "An unexpected server fault occurred."}
    )
