"""FastAPI application entrypoint for AetherMap-OSINT."""
import hashlib
import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.audit import init_audit, record_audit
from app.engines import history_diff, orchestrate_recon
from app.schemas import ReconRequest, ReconResponse
from app.security import auth_required, check_scan_rate_limit, client_key, require_api_key
from app.tls_assessment_v2 import assess_services_tls

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
logger=logging.getLogger("aethermap.main")
VERSION="3.3.0"

@asynccontextmanager
async def lifespan(app:FastAPI):
    init_audit(); logger.info("Initializing AetherMap-OSINT scanner %s",VERSION); yield; logger.info("Shutting down AetherMap-OSINT scanner")

app=FastAPI(title="AetherMap-OSINT API",description="Authorized-use OSINT attack-surface mapping with bounded TCP/UDP/TLS assessment and evidence-backed NVD/CPE correlation.",version=VERSION,docs_url="/docs",redoc_url="/redoc",openapi_url="/openapi.json",lifespan=lifespan)

def _configured_cors_origins()->list[str]:
    configured=os.getenv("ALLOWED_ORIGINS",""); return [o.strip() for o in configured.split(",") if o.strip()] if configured.strip() else ["http://localhost:5173","http://127.0.0.1:5173","http://localhost:3000","http://127.0.0.1:3000"]
app.add_middleware(CORSMiddleware,allow_origins=_configured_cors_origins(),allow_credentials=False,allow_methods=["GET","POST","OPTIONS"],allow_headers=["Content-Type","Accept","X-AetherMap-API-Key","X-Request-ID"])

@app.middleware("http")
async def request_context(request:Request,call_next):
    request.state.request_id=request.headers.get("X-Request-ID") or str(uuid.uuid4())
    try: response=await call_next(request)
    except Exception: raise
    response.headers["X-Request-ID"]=request.state.request_id; response.headers["Cache-Control"]="no-store"; return response

@app.get("/",tags=["System"],summary="Service health and capability summary",response_model=Dict[str,Any])
async def root_health_check():
    return {"service":"AetherMap-OSINT","status":"OPERATIONAL","version":VERSION,"authentication_required":auth_required(),"engines":{"crt_sh":"passive","dns":"real-public-DNS-only","tcp_scanner":"bounded-real-connect","udp_scanner":"bounded-probes","fingerprinting":"banner-and-protocol-evidence","tls":"protocol-cipher-chain-certificate-assessment","cve_correlator":"NVD-CPE-applicability"}}

@app.get("/api/health",tags=["System"],summary="Health probe")
async def health_check():return {"status":"ok","version":VERSION,"authentication_required":auth_required()}

@app.post("/api/recon",tags=["Reconnaissance"],summary="Run authorized discovery and bounded active scan",response_model=ReconResponse,status_code=status.HTTP_200_OK)
async def execute_recon(request:Request,payload:ReconRequest,api_key:str=Depends(require_api_key),x_forwarded_for:str|None=Header(default=None,alias="X-Forwarded-For"),host:str|None=Header(default=None)):
    actor=client_key(api_key,x_forwarded_for,host); check_scan_rate_limit(actor); request_id=request.state.request_id
    logger.info("Recon request target=%s max_assets=%s request_id=%s",payload.domain,payload.max_assets,request_id)
    try:
        response=await orchestrate_recon(payload.domain,ports=payload.ports,max_assets=payload.max_assets); response.services=await assess_services_tls(response.services)
        response.metadata.scanner_version=VERSION; response.metadata.authentication_required=auth_required(); response.metadata.rate_limit_per_window=max(1,min(int(os.getenv("SCAN_RATE_LIMIT","10")),60))
        actor_label="authenticated-api-key" if auth_required() else "anonymous-local"
        record_audit(actor_label,"recon",payload.domain,"success",request_id,{"max_assets":payload.max_assets,"ports":payload.ports})
        return response
    except HTTPException: raise
    except Exception as exc:
        record_audit("authenticated-api-key" if auth_required() else "anonymous-local","recon",payload.domain,"error",request_id,{"error_type":type(exc).__name__}); logger.exception("Reconnaissance failed for %s request_id=%s",payload.domain,request_id)
        raise HTTPException(status_code=502,detail="Reconnaissance upstream failed. Check server logs using the request ID.",headers={"X-Request-ID":request_id}) from exc

@app.get("/api/recon/history/{domain}",tags=["Reconnaissance"],summary="Compare the two latest scans")
async def get_history(domain:str,api_key:str=Depends(require_api_key)):
    try: normalized=ReconRequest(domain=domain).domain
    except ValueError as exc: raise HTTPException(status_code=422,detail=str(exc)) from exc
    return {"domain":normalized,**history_diff(normalized)}

@app.get("/api/recon/sample",tags=["Reconnaissance"],response_model=ReconResponse,summary="Return explicitly synthetic demo data")
async def get_sample_recon(api_key:str=Depends(require_api_key)):
    response=await orchestrate_recon("example.com",demo_mode=True); response.services=await assess_services_tls(response.services); response.metadata.scanner_version=VERSION; return response

@app.exception_handler(HTTPException)
async def http_exception_handler(request:Request,exc:HTTPException):
    rid=getattr(request.state,"request_id",str(uuid.uuid4())); return JSONResponse(status_code=exc.status_code,content={"error":"HTTPError","message":exc.detail,"request_id":rid},headers={**(exc.headers or {}),"X-Request-ID":rid})

@app.exception_handler(Exception)
async def global_exception_handler(request:Request,exc:Exception):
    rid=getattr(request.state,"request_id",str(uuid.uuid4())); logger.exception("Unhandled exception request_id=%s path=%s",rid,request.url.path); return JSONResponse(status_code=500,content={"error":"InternalServerError","message":"An unexpected server fault occurred.","request_id":rid},headers={"X-Request-ID":rid})
