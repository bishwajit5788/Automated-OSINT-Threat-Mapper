"""Passive asset discovery plus bounded, real TCP service fingerprinting.

Active scanning is intentionally limited to a caller-supplied list or a small
common-port profile. Use only against systems you are authorized to assess.
No exploitation is performed.
"""

import asyncio
import datetime
import hashlib
import json
import logging
import os
import re
import socket
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import httpx

from app.schemas import PortService, ReconMetadata, ReconResponse, SeverityLevel, Subdomain, Vulnerability, VulnerabilitySummary

logger = logging.getLogger("aethermap.engines")

DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5601, 5672, 6379, 6443, 8000, 8080, 8443, 9000, 9200, 27017]
PORT_NAMES = {21:"FTP",22:"SSH",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",111:"RPC",135:"MSRPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",465:"SMTPS",587:"SMTP",993:"IMAPS",995:"POP3S",1433:"MSSQL",1521:"Oracle",2049:"NFS",2375:"Docker",3000:"HTTP",3306:"MySQL",3389:"RDP",5000:"HTTP",5432:"PostgreSQL",5601:"Kibana",5672:"AMQP",6379:"Redis",6443:"Kubernetes API",8000:"HTTP",8080:"HTTP",8443:"HTTPS",9000:"HTTP",9200:"Elasticsearch",27017:"MongoDB"}
DB_PATH = Path(os.getenv("AETHERMAP_HISTORY_DB", "data/aethermap_history.sqlite3"))


def _history_init() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as db:
        db.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, scanned_at TEXT NOT NULL, fingerprint TEXT NOT NULL, payload TEXT NOT NULL)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain_time ON scans(domain, scanned_at)")


def _history_save(domain: str, payload: ReconResponse) -> str:
    _history_init()
    serialized = json.dumps(payload.model_dump(mode="json"), sort_keys=True)
    fingerprint = hashlib.sha256(serialized.encode()).hexdigest()
    with sqlite3.connect(DB_PATH) as db:
        previous = db.execute("SELECT fingerprint FROM scans WHERE domain=? ORDER BY id DESC LIMIT 1", (domain,)).fetchone()
        db.execute("INSERT INTO scans(domain, scanned_at, fingerprint, payload) VALUES(?,?,?,?)", (domain, payload.timestamp, fingerprint, serialized))
    if not previous:
        return "baseline"
    if previous[0] == fingerprint:
        return "unchanged"
    old = json.loads(db.execute("SELECT payload FROM scans WHERE domain=? ORDER BY id DESC LIMIT 2", (domain,)).fetchone()[0]) if False else None
    return "changed"


def history_diff(domain: str) -> Dict[str, List]:
    """Return a compact diff between the two most recent stored scans."""
    _history_init()
    with sqlite3.connect(DB_PATH) as db:
        rows = db.execute("SELECT payload FROM scans WHERE domain=? ORDER BY id DESC LIMIT 2", (domain,)).fetchall()
    if len(rows) < 2:
        return {"added_ports": [], "removed_ports": [], "added_assets": [], "removed_assets": []}
    current, previous = (json.loads(rows[0][0]), json.loads(rows[1][0]))
    ports_now = {s["port"] for s in current.get("services", [])}
    ports_old = {s["port"] for s in previous.get("services", [])}
    assets_now = {s["name"] for s in current.get("subdomains", [])}
    assets_old = {s["name"] for s in previous.get("subdomains", [])}
    return {"added_ports": sorted(ports_now - ports_old), "removed_ports": sorted(ports_old - ports_now), "added_assets": sorted(assets_now - assets_old), "removed_assets": sorted(assets_old - assets_now)}


async def resolve_dns_async(domain: str) -> Tuple[str, bool]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        return (infos[0][4][0], True) if infos else ("Unknown", False)
    except (socket.gaierror, socket.herror, TimeoutError, OSError) as exc:
        logger.warning("DNS resolution failed for '%s': %s", domain, exc)
        return "Unknown", False


async def query_crt_sh(domain: str, *, demo_mode: bool = False) -> Tuple[List[Subdomain], str]:
    subdomains, seen, status_msg = [], set(), "Success"
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
            response = await client.get(url, headers={"User-Agent":"AetherMap-OSINT/2.0"})
            if response.status_code != 200:
                return [], f"crt.sh HTTP {response.status_code}"
            for entry in response.json():
                for raw in str(entry.get("name_value", "")).splitlines():
                    name = raw.strip().lower().removeprefix("*.")
                    if name and (name == domain or name.endswith(f".{domain}")) and name not in seen:
                        seen.add(name)
                        subdomains.append(Subdomain(name=name, source="crt.sh", last_seen=str(entry.get("not_before", "Unknown"))))
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        status_msg = f"crt.sh error: {type(exc).__name__}"
    return subdomains[:100], status_msg


def _ports(requested: Optional[List[int]]) -> List[int]:
    if requested:
        return requested
    raw = os.getenv("SCAN_PORTS", "")
    if raw:
        try:
            parsed = sorted({int(p.strip()) for p in raw.split(",") if p.strip()})
            if len(parsed) <= 128 and all(1 <= p <= 65535 for p in parsed):
                return parsed
        except ValueError:
            pass
    return DEFAULT_PORTS


async def _tcp_probe(ip: str, port: int, timeout: float = 1.5) -> Optional[bytes]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        try:
            if port in {80, 3000, 5000, 8000, 8080, 8443, 9000}:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n")
                await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=1.2)
            return data
        finally:
            writer.close()
            await writer.wait_closed()
    except (OSError, asyncio.TimeoutError):
        return None


def _fingerprint(port: int, data: bytes) -> Tuple[str, str, str, str]:
    text = data.decode("utf-8", errors="ignore")[:512].replace("\r", " ").replace("\n", " ").strip()
    service = PORT_NAMES.get(port, "Unknown")
    product, version = service, "Unknown"
    if text.startswith("SSH-"):
        service = "SSH"
        m = re.search(r"SSH-[^ ]+-(OpenSSH|dropbear)[_/ -]?([0-9][^ ]*)", text, re.I)
        if m: product, version = m.group(1), m.group(2)
    elif text.startswith("HTTP/"):
        service = "HTTPS" if port in {443,8443} else "HTTP"
        server = re.search(r"Server:\s*([^ ]+)", text, re.I)
        if server:
            product = server.group(1)
            vm = re.search(r"([0-9]+(?:\.[0-9]+)+)", product)
            version = vm.group(1) if vm else "Unknown"
    elif port == 6379 and text:
        product = "Redis"
    elif port == 9200 and text:
        product = "Elasticsearch"
    return service, product, version, text or "No banner"


async def scan_tcp_services(ip: str, ports: List[int]) -> List[PortService]:
    results = await asyncio.gather(*[_tcp_probe(ip, port) for port in ports])
    services = []
    for port, data in zip(ports, results):
        if data is not None:
            service, product, version, banner = _fingerprint(port, data)
            services.append(PortService(port=port, service_name=service, product=product, version=version, banner=banner, status="open"))
    return services


def _cpe_candidates(product: str) -> List[str]:
    p = product.lower()
    mappings = {"openssh":["openbsd:openssh"], "apache":["apache:http_server"], "nginx":["nginx:nginx"], "redis":["redis:redis"], "elasticsearch":["elastic:elasticsearch"], "mysql":["oracle:mysql"], "postgresql":["postgresql:postgresql"], "mongodb":["mongodb:mongodb"], "tomcat":["apache:tomcat"]}
    return mappings.get(next((k for k in mappings if k in p), ""), [])


async def correlate_nvd(service: PortService) -> PortService:
    """Resolve product candidates through NVD CPE search, then query CVEs by exact CPE.

    If product/version fingerprinting is weak, findings are returned with low/medium
    confidence rather than being represented as confirmed vulnerabilities.
    """
    candidates = _cpe_candidates(service.product)
    if not candidates or service.version == "Unknown":
        return service
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            cpe_ref = None
            for keyword in candidates:
                r = await client.get("https://services.nvd.nist.gov/rest/json/cpes/2.0", params={"keywordSearch": keyword, "resultsPerPage": 20})
                if r.status_code != 200: continue
                for item in r.json().get("products", []):
                    cpe = item.get("cpe", {}).get("cpeName", [{}])[0].get("cpeName")
                    if cpe and cpe.startswith("cpe:2.3:a:"):
                        cpe_ref = cpe
                        break
                if cpe_ref: break
            if not cpe_ref:
                return service
            # Replace wildcard version in the dictionary name with the observed version.
            parts = cpe_ref.split(":")
            if len(parts) >= 6:
                parts[5] = service.version
                exact_cpe = ":".join(parts)
            else:
                exact_cpe = cpe_ref
            r = await client.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cpeName": exact_cpe, "resultsPerPage": 50})
            if r.status_code != 200: return service
            vulns = []
            for item in r.json().get("vulnerabilities", []):
                cve = item.get("cve", {})
                metrics = cve.get("metrics", {})
                metric = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV40") or [{}])[0]
                cvss = metric.get("cvssData", {})
                score = float(cvss.get("baseScore", 0.0) or 0.0)
                severity = SeverityLevel.CRITICAL if score >= 9 else SeverityLevel.HIGH if score >= 7 else SeverityLevel.MEDIUM if score >= 4 else SeverityLevel.LOW if score > 0 else SeverityLevel.INFO
                desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "NVD vulnerability")
                vulns.append(Vulnerability(cve_id=cve.get("id", "Unknown"), severity=severity, cvss_score=score, description=desc[:600], service=service.service_name, port=service.port, confidence="correlated-cpe", source="NVD"))
            service.cpe = exact_cpe
            service.vulnerabilities = vulns[:25]
    except (httpx.HTTPError, ValueError, KeyError, IndexError) as exc:
        logger.warning("NVD correlation failed for %s:%s: %s", service.product, service.version, exc)
    return service


def compute_threat_metrics(services: List[PortService], subdomains: List[Subdomain]) -> Tuple[int, str, VulnerabilitySummary]:
    counts = {level: 0 for level in SeverityLevel}
    for service in services:
        for vuln in service.vulnerabilities: counts[vuln.severity] += 1
    total = sum(counts.values())
    raw = counts[SeverityLevel.CRITICAL]*28 + counts[SeverityLevel.HIGH]*15 + counts[SeverityLevel.MEDIUM]*6 + counts[SeverityLevel.LOW]*2 + len(services)*2 + min(len(subdomains),10)
    score = min(100, max(0, raw))
    risk = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 35 else "LOW" if score else "CLEAN"
    return score, risk, VulnerabilitySummary(critical=counts[SeverityLevel.CRITICAL], high=counts[SeverityLevel.HIGH], medium=counts[SeverityLevel.MEDIUM], low=counts[SeverityLevel.LOW], info=counts[SeverityLevel.INFO], total=total)


async def orchestrate_recon(domain: str, *, demo_mode: bool = False, ports: Optional[List[int]] = None) -> ReconResponse:
    started = time.perf_counter()
    (ip, dns_ok), (subdomains, crt_status) = await asyncio.gather(resolve_dns_async(domain), query_crt_sh(domain, demo_mode=demo_mode))
    scan_ports = _ports(ports)
    services = await scan_tcp_services(ip, scan_ports) if dns_ok and not demo_mode else []
    if demo_mode:
        # Keep demo endpoint intentionally synthetic and isolated from live scanning.
        from app.demo_data import demo_services
        services = demo_services()
    services = await asyncio.gather(*[correlate_nvd(s) for s in services]) if services else []
    for sub in subdomains:
        if sub.name == domain:
            sub.ip, sub.status = ip if dns_ok else "Unknown", "resolved" if dns_ok else "unresolved"
    score, risk, summary = compute_threat_metrics(services, subdomains)
    elapsed = round((time.perf_counter()-started)*1000, 2)
    response = ReconResponse(target_domain=domain, root_ip=ip, timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(), threat_score=score, risk_level=risk, subdomains=subdomains, services=list(services), vulnerability_summary=summary, metadata=ReconMetadata(execution_time_ms=elapsed, sources_queried=["DNS","Certificate Transparency (crt.sh)","TCP connect scanner","NVD CPE/CVE API"], dns_resolved=dns_ok, crt_sh_status=crt_status, network_intel_status="local TCP scanner", findings_mode="demo" if demo_mode else "passive-active", scan_ports=scan_ports, open_ports=len(services)))
    change = _history_save(domain, response)
    response.metadata.historical_change = change
    return response
