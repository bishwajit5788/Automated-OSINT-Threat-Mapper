"""Pydantic schemas and data validation models for AetherMap-OSINT."""

import re
from enum import Enum
from typing import List

from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    """Vulnerability severity classification."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ReconRequest(BaseModel):
    """Reconnaissance task initiation payload."""

    domain: str = Field(
        ...,
        min_length=3,
        max_length=253,
        description="Target DNS hostname. Active reconnaissance must be authorized.",
        examples=["example.com"],
    )

    @field_validator("domain")
    @classmethod
    def sanitize_domain(cls, v: str) -> str:
        """Normalize an FQDN and reject URLs, IP literals, localhost, and malformed names."""
        clean = v.strip().lower()
        clean = re.sub(r"^https?://", "", clean)
        clean = clean.split("/")[0].split(":")[0].strip().rstrip(".")

        if not clean or clean == "localhost":
            raise ValueError("A public DNS hostname is required.")

        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", clean):
            raise ValueError("IP literals are not accepted; provide a DNS hostname.")

        labels = clean.split(".")
        if len(labels) < 2 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("Invalid domain format. Provide a valid FQDN such as example.com.")

        return clean


class Subdomain(BaseModel):
    """Discovered subdomain entity model."""

    name: str
    ip: str = "Unknown"
    status: str = "Unknown"
    source: str = "crt.sh"
    last_seen: str = "Unknown"


class Vulnerability(BaseModel):
    """Correlated vulnerability entity model."""

    cve_id: str
    severity: SeverityLevel = SeverityLevel.INFO
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    description: str = "Unknown"
    service: str = "Unknown"
    port: int = Field(default=0, ge=0, le=65535)
    remediation: str = "Review the vendor advisory and apply the supported security update."
    confidence: str = "unknown"
    source: str = "unknown"


class PortService(BaseModel):
    """Observed network service model."""

    port: int = Field(..., ge=1, le=65535)
    protocol: str = "tcp"
    service_name: str = "Unknown"
    product: str = "Unknown"
    version: str = "Unknown"
    banner: str = "Unknown"
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    status: str = "observed"


class VulnerabilitySummary(BaseModel):
    """Aggregated severity counts."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0


class ReconMetadata(BaseModel):
    """Execution telemetry and source diagnostics."""

    execution_time_ms: float = 0.0
    sources_queried: List[str] = Field(default_factory=list)
    dns_resolved: bool = False
    crt_sh_status: str = "not-run"
    network_intel_status: str = "not-run"
    findings_mode: str = "simulated"
    authorized_use_only: bool = True


class ReconResponse(BaseModel):
    """Complete synthesized attack-surface dossier."""

    target_domain: str
    root_ip: str = "Unknown"
    timestamp: str
    threat_score: int = Field(ge=0, le=100)
    risk_level: str
    subdomains: List[Subdomain] = Field(default_factory=list)
    services: List[PortService] = Field(default_factory=list)
    vulnerability_summary: VulnerabilitySummary = Field(default_factory=VulnerabilitySummary)
    metadata: ReconMetadata = Field(default_factory=ReconMetadata)
