"""Transparent confidence scoring from independently observed evidence."""
from __future__ import annotations
from app.schemas import PortService, Vulnerability


def evidence_confidence(service: PortService) -> float:
    values=[float(e.confidence) for e in service.evidence]
    if not values:return 0.0
    # Independent evidence should raise confidence, but never manufacture certainty.
    score=1.0
    for value in sorted(values,reverse=True)[:5]: score*=max(0.0,min(1.0,value))
    combined=1.0-(1.0-score)**0.5
    if service.ip!="Unknown": combined=max(combined,0.75)
    if service.product!="Unknown": combined=min(1.0,combined+0.10)
    if service.version!="Unknown": combined=min(1.0,combined+0.10)
    if service.cpe: combined=min(1.0,combined+0.05)
    return round(max(0.0,min(1.0,combined)),3)


def vulnerability_confidence(service: PortService, vulnerability: Vulnerability) -> float:
    evidence=max((e.confidence for e in vulnerability.evidence),default=0.0)
    service_score=evidence_confidence(service)
    cpe_bonus=0.10 if service.cpe and vulnerability.source.lower().startswith("nvd") else 0.0
    version_bonus=0.10 if service.version!="Unknown" else 0.0
    return round(min(1.0,max(evidence,service_score*0.7)+cpe_bonus+version_bonus),3)


def apply_confidence(services:list[PortService])->list[PortService]:
    for service in services:
        service.confidence_score=evidence_confidence(service)
        for vuln in service.vulnerabilities:
            score=vulnerability_confidence(service,vuln)
            vuln.confidence_score=score
            vuln.confidence="high" if score>=.85 else "medium" if score>=.60 else "low" if score>=.35 else "unknown"
    return services
