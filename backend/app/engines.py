"""Asynchronous OSINT reconnaissance engines and intelligence orchestration.

The network-intelligence catalog in this module is DEMO data. It must never be
presented as a real Shodan result for an arbitrary domain.
"""

import asyncio
import datetime
import logging
import socket
import time
from typing import List, Set, Tuple

import httpx

from app.schemas import (
    PortService,
    ReconMetadata,
    ReconResponse,
    SeverityLevel,
    Subdomain,
    Vulnerability,
    VulnerabilitySummary,
)

logger = logging.getLogger("aethermap.engines")


async def resolve_dns_async(domain: str) -> Tuple[str, bool]:
    """Resolve a domain to an IPv4 address without blocking the event loop."""
    loop = asyncio.get_running_loop()
    try:
        addr_info = await loop.getaddrinfo(
            domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
        if addr_info:
            return addr_info[0][4][0], True
    except (socket.gaierror, socket.herror, TimeoutError, OSError) as exc:
        logger.warning("DNS resolution failed for '%s': %s", domain, exc)
    return "Unknown", False


async def query_crt_sh(domain: str, *, demo_mode: bool = False) -> Tuple[List[Subdomain], str]:
    """Query crt.sh passively and return certificate-observed hostnames.

    A small demo fallback is allowed only when demo_mode=True. Production scans
    return an empty list when the upstream is unavailable instead of fabricating
    discovered assets.
    """
    subdomains: List[Subdomain] = []
    seen_names: Set[str] = set()
    status_msg = "Success"
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {"User-Agent": "AetherMap-OSINT/1.1 (+authorized-security-research)"}

    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            response = await client.get(url, headers=headers)
            if response.status_code != 200:
                status_msg = f"crt.sh HTTP {response.status_code}"
            else:
                payload = response.json()
                if not isinstance(payload, list):
                    raise ValueError("crt.sh response was not a JSON list")
                for entry in payload:
                    for raw_name in str(entry.get("name_value", "")).splitlines():
                        cleaned = raw_name.strip().lower().removeprefix("*.")
                        if (
                            cleaned
                            and cleaned == domain or cleaned.endswith(f".{domain}")
                        ) and cleaned not in seen_names:
                            seen_names.add(cleaned)
                            subdomains.append(
                                Subdomain(
                                    name=cleaned,
                                    ip="Unknown",
                                    status="certificate-observed",
                                    source="crt.sh",
                                    last_seen=str(entry.get("not_before", "Unknown")),
                                )
                            )
    except (httpx.HTTPError, ValueError) as exc:
        status_msg = f"crt.sh error: {type(exc).__name__}"
        logger.warning("crt.sh query failed for '%s': %s", domain, exc)
    except Exception as exc:
        status_msg = f"crt.sh engine error: {type(exc).__name__}"
        logger.exception("Unexpected crt.sh failure for '%s'", domain)

    if demo_mode and not subdomains:
        for prefix in ("www", "api", "mail"):
            name = f"{prefix}.{domain}"
            subdomains.append(
                Subdomain(
                    name=name,
                    ip="Unknown",
                    status="demo",
                    source="DEMO_DATA",
                    last_seen="synthetic",
                )
            )
        status_msg = "DEMO fallback"

    return subdomains[:25], status_msg


DEMO_SERVICES = [
    PortService(
        port=22,
        protocol="tcp",
        service_name="OpenSSH",
        product="OpenSSH",
        version="8.2p1 (demo)",
        banner="DEMO: SSH-2.0-OpenSSH_8.2p1",
        status="demo",
        vulnerabilities=[
            Vulnerability(
                cve_id="CVE-2023-38408",
                severity=SeverityLevel.CRITICAL,
                cvss_score=9.8,
                description="OpenSSH ssh-agent PKCS#11 search-path issue. Demo finding only; confirm exact package and configuration before treating as applicable.",
                service="OpenSSH",
                port=22,
                remediation="Upgrade OpenSSH to a supported fixed release and review agent forwarding policy.",
                confidence="demo",
                source="NVD",
            )
        ],
    ),
    PortService(
        port=443,
        protocol="tcp",
        service_name="HTTPS",
        product="TLS endpoint",
        version="demo",
        banner="DEMO: HTTPS endpoint",
        status="demo",
        vulnerabilities=[],
    ),
    PortService(
        port=8080,
        protocol="tcp",
        service_name="HTTP-Alt",
        product="Apache Tomcat / Log4j",
        version="9.0.41 / 2.14.1 (demo)",
        banner="DEMO: Apache-Coyote/1.1; Log4j-Core 2.14.1",
        status="demo",
        vulnerabilities=[
            Vulnerability(
                cve_id="CVE-2021-44228",
                severity=SeverityLevel.CRITICAL,
                cvss_score=10.0,
                description="Log4j JNDI lookup vulnerability. Demo finding only; applicability requires verified Log4j component/version/configuration.",
                service="Log4j",
                port=8080,
                remediation="Upgrade the affected Log4j component to a supported fixed release and verify the deployed dependency tree.",
                confidence="demo",
                source="NVD",
            )
        ],
    ),
]


async def query_network_intelligence(*, demo_mode: bool = True) -> Tuple[List[PortService], str]:
    """Return demo network intelligence until a real provider is explicitly integrated.

    No port scan or Shodan lookup is performed by this repository version.
    """
    await asyncio.sleep(0)
    if demo_mode:
        return [service.model_copy(deep=True) for service in DEMO_SERVICES], "Demo catalog"
    return [], "Not configured"


def compute_threat_metrics(
    services: List[PortService], subdomains: List[Subdomain]
) -> Tuple[int, str, VulnerabilitySummary]:
    """Calculate a transparent heuristic score from observed/correlated findings."""
    counts = {level: 0 for level in SeverityLevel}
    for service in services:
        for vuln in service.vulnerabilities:
            counts[vuln.severity] += 1

    total = sum(counts.values())
    raw_score = (
        counts[SeverityLevel.CRITICAL] * 28
        + counts[SeverityLevel.HIGH] * 15
        + counts[SeverityLevel.MEDIUM] * 6
        + counts[SeverityLevel.LOW] * 2
        + len(services) * 2
        + min(len(subdomains), 10)
    )
    score = min(100, max(0, raw_score))
    risk = (
        "CRITICAL" if score >= 80 else
        "HIGH" if score >= 60 else
        "MEDIUM" if score >= 35 else
        "LOW" if score > 0 else "CLEAN"
    )
    summary = VulnerabilitySummary(
        critical=counts[SeverityLevel.CRITICAL],
        high=counts[SeverityLevel.HIGH],
        medium=counts[SeverityLevel.MEDIUM],
        low=counts[SeverityLevel.LOW],
        info=counts[SeverityLevel.INFO],
        total=total,
    )
    return score, risk, summary


async def orchestrate_recon(domain: str, *, demo_mode: bool = False) -> ReconResponse:
    """Run DNS and passive CT discovery concurrently; use only explicit demo data for service findings."""
    started = time.perf_counter()
    (ip, dns_ok), (subdomains, crt_status) = await asyncio.gather(
        resolve_dns_async(domain),
        query_crt_sh(domain, demo_mode=demo_mode),
    )
    services, network_status = await query_network_intelligence(demo_mode=demo_mode)

    for subdomain in subdomains:
        if subdomain.name == domain:
            subdomain.ip = ip if dns_ok else "Unknown"
            subdomain.status = "resolved" if dns_ok else "unresolved"

    score, risk, summary = compute_threat_metrics(services, subdomains)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

    metadata = ReconMetadata(
        execution_time_ms=elapsed_ms,
        sources_queried=["DNS", "Certificate Transparency (crt.sh)"] + (["DEMO service catalog"] if demo_mode else []),
        dns_resolved=dns_ok,
        crt_sh_status=crt_status,
        network_intel_status=network_status,
        findings_mode="demo" if demo_mode else "passive",
    )

    return ReconResponse(
        target_domain=domain,
        root_ip=ip,
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        threat_score=score,
        risk_level=risk,
        subdomains=subdomains,
        services=services,
        vulnerability_summary=summary,
        metadata=metadata,
    )
