"""Pydantic schemas and data validation models for AetherMap-OSINT."""

from enum import Enum
from typing import List, Optional
import re
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
        description="Target domain to perform OSINT threat mapping on (e.g. example.com)",
        examples=["tesla.com", "uber.com", "github.com"]
    )

    @field_validator("domain")
    @classmethod
    def sanitize_domain(cls, v: str) -> str:
        """Sanitize domain string, removing protocol prefixes, paths, and invalid characters."""
        if not v or not v.strip():
            raise ValueError("Domain cannot be empty.")
        clean = v.strip().lower()
        clean = re.sub(r"^https?://", "", clean)
        clean = clean.split("/")[0].split(":")[0].strip()
        # Basic domain format check
        domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if not re.match(domain_pattern, clean) and clean != "localhost":
            raise ValueError(f"Invalid domain format: '{clean}'. Must be a valid FQDN (e.g. example.com).")
        return clean


class Subdomain(BaseModel):
    """Discovered subdomain entity model."""
    name: str = Field(..., description="Fully qualified subdomain name")
    ip: str = Field(default="Unknown", description="Resolved IPv4/IPv6 address or 'Unknown'")
    status: str = Field(default="Active", description="Host resolution status")
    source: str = Field(default="crt.sh", description="Intelligence discovery source")
    last_seen: str = Field(default="Unknown", description="Certificate timestamp or discovery record")


class Vulnerability(BaseModel):
    """Correlated CVE vulnerability entity model."""
    cve_id: str = Field(..., description="Common Vulnerabilities and Exposures identifier")
    severity: SeverityLevel = Field(default=SeverityLevel.LOW, description="Severity ranking")
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0, description="Common Vulnerability Scoring System v3.1 score")
    description: str = Field(default="Unknown", description="CVE threat description and vector impact")
    service: str = Field(default="Unknown", description="Affected network service")
    port: int = Field(default=0, description="Target port number")
    remediation: str = Field(default="Apply vendor security patches and restrict firewall ACLs.", description="Mitigation guidance")


class PortService(BaseModel):
    """Exposed network port and service fingerprint model."""
    port: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: str = Field(default="tcp", description="Transport layer protocol")
    service_name: str = Field(default="Unknown", description="Identified application service")
    product: str = Field(default="Unknown", description="Detected product/daemon name")
    version: str = Field(default="Unknown", description="Service release version")
    banner: str = Field(default="Unknown", description="Service banner response snippet")
    vulnerabilities: List[Vulnerability] = Field(default_factory=list, description="Associated CVE vulnerabilities")
    status: str = Field(default="open", description="Port operational state")


class VulnerabilitySummary(BaseModel):
    """Aggregated threat metric summary."""
    critical: int = Field(default=0, description="Count of CRITICAL severity CVEs")
    high: int = Field(default=0, description="Count of HIGH severity CVEs")
    medium: int = Field(default=0, description="Count of MEDIUM severity CVEs")
    low: int = Field(default=0, description="Count of LOW severity CVEs")
    total: int = Field(default=0, description="Total detected vulnerability signatures")


class ReconMetadata(BaseModel):
    """Execution telemetry and diagnostics metadata."""
    execution_time_ms: float = Field(default=0.0, description="Total pipeline latency in milliseconds")
    sources_queried: List[str] = Field(default_factory=list, description="OSINT data sources queried")
    dns_resolved: bool = Field(default=True, description="Whether DNS resolution succeeded")
    crt_sh_status: str = Field(default="Success", description="Certificate Transparency engine status")
    shodan_status: str = Field(default="Success", description="Network footprint engine status")


class ReconResponse(BaseModel):
    """Complete synthesized attack surface intelligence dossier."""
    target_domain: str = Field(..., description="Scanned target domain")
    root_ip: str = Field(default="Unknown", description="Resolved root domain IP address")
    timestamp: str = Field(..., description="ISO 8601 scan completion timestamp")
    threat_score: int = Field(..., ge=0, le=100, description="Calculated composite risk score (0-100)")
    risk_level: str = Field(..., description="Risk tier: CRITICAL, HIGH, MEDIUM, LOW, or CLEAN")
    subdomains: List[Subdomain] = Field(default_factory=list, description="Discovered domain assets")
    services: List[PortService] = Field(default_factory=list, description="Exposed network attack surfaces")
    vulnerability_summary: VulnerabilitySummary = Field(default_factory=VulnerabilitySummary, description="Threat count matrix")
    metadata: ReconMetadata = Field(default_factory=ReconMetadata, description="Scan execution diagnostics")
