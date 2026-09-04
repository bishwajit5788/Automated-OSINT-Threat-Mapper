"""Pydantic schemas for AetherMap-OSINT."""

import re
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ReconRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253, examples=["example.com"])
    ports: Optional[List[int]] = Field(default=None, max_length=128)
    max_assets: int = Field(default=25, ge=1, le=100)

    @field_validator("domain")
    @classmethod
    def sanitize_domain(cls, v: str) -> str:
        clean = v.strip().lower()
        clean = re.sub(r"^https?://", "", clean).split("/")[0].split(":")[0].rstrip(".")
        if not clean or clean == "localhost":
            raise ValueError("A public DNS hostname is required.")
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", clean):
            raise ValueError("IP literals are not accepted; provide a DNS hostname.")
        labels = clean.split(".")
        if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
            raise ValueError("Invalid domain format. Provide a valid FQDN such as example.com.")
        return clean

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: Optional[List[int]]) -> Optional[List[int]]:
        if v is None:
            return v
        if any(port < 1 or port > 65535 for port in v):
            raise ValueError("Ports must be between 1 and 65535.")
        return sorted(set(v))


class Subdomain(BaseModel):
    name: str
    ip: str = "Unknown"
    status: str = "Unknown"
    source: str = "crt.sh"
    last_seen: str = "Unknown"
    scanned: bool = False


class Evidence(BaseModel):
    type: str
    value: str
    source: str
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class Vulnerability(BaseModel):
    cve_id: str
    severity: SeverityLevel = SeverityLevel.INFO
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    description: str = "Unknown"
    service: str = "Unknown"
    port: int = Field(default=0, ge=0, le=65535)
    remediation: str = "Review the vendor advisory and apply the supported security update."
    confidence: str = "unknown"
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    source: str = "unknown"
    evidence: List[Evidence] = Field(default_factory=list)


class PortService(BaseModel):
    host: str = "Unknown"
    ip: str = "Unknown"
    port: int = Field(..., ge=1, le=65535)
    protocol: str = "tcp"
    service_name: str = "Unknown"
    product: str = "Unknown"
    version: str = "Unknown"
    banner: str = "Unknown"
    cpe: Optional[str] = None
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    evidence: List[Evidence] = Field(default_factory=list)
    status: str = "open"


class VulnerabilitySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0


class ReconMetadata(BaseModel):
    execution_time_ms: float = 0.0
    sources_queried: List[str] = Field(default_factory=list)
    dns_resolved: bool = False
    crt_sh_status: str = "not-run"
    network_intel_status: str = "not-run"
    findings_mode: str = "passive-active"
    scan_ports: List[int] = Field(default_factory=list)
    open_ports: int = 0
    hosts_scanned: int = 0
    historical_change: str = "baseline"
    authorized_use_only: bool = True
    scanner_version: str = "3.0.0"


class ReconResponse(BaseModel):
    target_domain: str
    root_ip: str = "Unknown"
    timestamp: str
    threat_score: int = Field(ge=0, le=100)
    risk_level: str
    subdomains: List[Subdomain] = Field(default_factory=list)
    services: List[PortService] = Field(default_factory=list)
    vulnerability_summary: VulnerabilitySummary = Field(default_factory=VulnerabilitySummary)
    metadata: ReconMetadata = Field(default_factory=ReconMetadata)
