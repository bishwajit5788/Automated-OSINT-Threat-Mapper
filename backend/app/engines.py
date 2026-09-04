"""Production-oriented passive discovery, safe TCP scanning and NVD correlation.

The scanner performs bounded TCP connect checks and non-destructive protocol
fingerprinting. It never exploits a service. Use only on systems you are
authorized to assess.
"""

import asyncio
import datetime as dt
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import sqlite3
import ssl
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import httpx

from app.schemas import Evidence, PortService, ReconMetadata, ReconResponse, SeverityLevel, Subdomain, Vulnerability, VulnerabilitySummary

logger = logging.getLogger("aethermap.engines")
SCANNER_VERSION = "3.0.0"
DEFAULT_PORTS = [21,22,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1433,1521,2049,2375,3000,3306,3389,5000,5432,5601,5672,6379,6443,8000,8080,8443,9000,9200,27017]
HTTP_PORTS = {80,3000,5000,8000,8080,8443,9000}
TLS_PORTS = {443,465,563,636,853,993,995,8443}
PORT_NAMES = {21:"FTP",22:"SSH",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",111:"RPC",135:"MSRPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",465:"SMTPS",587:"SMTP",993:"IMAPS",995:"POP3S",1433:"MSSQL",1521:"Oracle",2049:"NFS",2375:"Docker",3000:"HTTP",3306:"MySQL",3389:"RDP",5000:"HTTP",5432:"PostgreSQL",5601:"Kibana",5672:"AMQP",6379:"Redis",6443:"Kubernetes API",8000:"HTTP",8080:"HTTP",8443:"HTTPS",9000:"HTTP",9200:"Elasticsearch",27017:"MongoDB"}
PRODUCT_CPE_KEYWORDS = {"openssh":"openbsd:openssh", "apache":"apache:http_server", "nginx":"nginx:nginx", "redis":"redis:redis", "elasticsearch":"elastic:elasticsearch", "mysql":"oracle:mysql", "postgresql":"postgresql:postgresql", "mongodb":"mongodb:mongodb", "tomcat":"apache:tomcat"}
DB_PATH = Path(os.getenv("AETHERMAP_HISTORY_DB", "data/aethermap_history.sqlite3"))
MAX_CONCURRENCY = max(1, min(int(os.getenv("SCAN_CONCURRENCY", "32")), 128))
MAX_ASSETS = max(1, min(int(os.getenv("MAX_ASSETS", "25")), 100))
CONNECT_TIMEOUT = float(os.getenv("SCAN_CONNECT_TIMEOUT", "1.5"))
NVD_TIMEOUT = float(os.getenv("NVD_TIMEOUT", "10"))


def _history_init() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as db:
        db.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, scanned_at TEXT NOT NULL, fingerprint TEXT NOT NULL, payload TEXT NOT NULL)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain_time ON scans(domain, scanned_at)")


def _stable_payload(payload: ReconResponse) -> dict:
    data = payload.model_dump(mode="json")
    data.pop("timestamp", None)
    meta = data.get("metadata", {})
    for key in ("execution_time_ms", "historical_change"):
        meta.pop(key, None)
    data["metadata"] = meta
    return data


def _history_save(domain: str, payload: ReconResponse) -> str:
    _history_init()
    serialized = json.dumps(payload.model_dump(mode="json"), sort_keys=True)
    stable = json.dumps(_stable_payload(payload), sort_keys=True)
    fingerprint = hashlib.sha256(stable.encode()).hexdigest()
    with sqlite3.connect(DB_PATH) as db:
        previous = db.execute("SELECT fingerprint FROM scans WHERE domain=? ORDER BY id DESC LIMIT 1", (domain,)).fetchone()
        db.execute("INSERT INTO scans(domain, scanned_at, fingerprint, payload) VALUES(?,?,?,?)", (domain, payload.timestamp, fingerprint, serialized))
    return "baseline" if not previous else ("unchanged" if previous[0] == fingerprint else "changed")


def history_diff(domain: str) -> Dict[str, List]:
    _history_init()
    with sqlite3.connect(DB_PATH) as db:
        rows = db.execute("SELECT payload FROM scans WHERE domain=? ORDER BY id DESC LIMIT 2", (domain,)).fetchall()
    if len(rows) < 2:
        return {"added_ports": [], "removed_ports": [], "added_assets": [], "removed_assets": [], "changed_services": []}
    current, previous = json.loads(rows[0][0]), json.loads(rows[1][0])
    key = lambda s: (s.get("host"), s.get("port"), s.get("protocol", "tcp"))
    now_services = {key(s): s for s in current.get("services", [])}
    old_services = {key(s): s for s in previous.get("services", [])}
    changed = []
    for k in sorted(now_services.keys() & old_services.keys(), key=str):
        a, b = now_services[k], old_services[k]
        if (a.get("product"), a.get("version"), a.get("cpe"), sorted(v.get("cve_id") for v in a.get("vulnerabilities", []))) != (b.get("product"), b.get("version"), b.get("cpe"), sorted(v.get("cve_id") for v in b.get("vulnerabilities", []))):
            changed.append({"host": k[0], "port": k[1], "protocol": k[2]})
    ports_now = {k[1] for k in now_services}; ports_old = {k[1] for k in old_services}
    assets_now = {s["name"] for s in current.get("subdomains", [])}; assets_old = {s["name"] for s in previous.get("subdomains", [])}
    return {"added_ports": sorted(ports_now-ports_old), "removed_ports": sorted(ports_old-ports_now), "added_assets": sorted(assets_now-assets_old), "removed_assets": sorted(assets_old-assets_now), "changed_services": changed}


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return False


async def resolve_host(host: str) -> List[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, socket.herror, TimeoutError, OSError) as exc:
        logger.warning("DNS resolution failed for %s: %s", host, exc)
        return []
    values = []
    for info in infos:
        ip = info[4][0]
        if _is_public_ip(ip) and ip not in values:
            values.append(ip)
    return values[:4]


async def resolve_dns_async(domain: str) -> Tuple[str, bool]:
    ips = await resolve_host(domain)
    return (ips[0], True) if ips else ("Unknown", False)


async def query_crt_sh(domain: str) -> Tuple[List[Subdomain], str]:
    subdomains, seen = [], set()
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True, headers={"User-Agent": f"AetherMap-OSINT/{SCANNER_VERSION}"}) as client:
            response = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
            if response.status_code != 200:
                return [], f"crt.sh HTTP {response.status_code}"
            for entry in response.json():
                for raw in str(entry.get("name_value", "")).splitlines():
                    name = raw.strip().lower().removeprefix("*.")
                    if name and (name == domain or name.endswith(f".{domain}")) and name not in seen:
                        seen.add(name)
                        subdomains.append(Subdomain(name=name, source="crt.sh", last_seen=str(entry.get("not_before", "Unknown"))))
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        return [], f"crt.sh error: {type(exc).__name__}"
    # Root first; scanning is bounded to prevent accidental fan-out.
    subdomains.sort(key=lambda x: (x.name != domain, x.name))
    return subdomains[:MAX_ASSETS], "Success"


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


async def _tcp_probe(ip: str, port: int, semaphore: asyncio.Semaphore) -> Optional[bytes]:
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=CONNECT_TIMEOUT)
            try:
                if port in HTTP_PORTS:
                    writer.write(b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: AetherMap-Scanner/3.0\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                elif port == 22:
                    writer.write(b"\r\n")
                    await writer.drain()
                return await asyncio.wait_for(reader.read(2048), timeout=1.5)
            finally:
                writer.close()
                try: await writer.wait_closed()
                except Exception: pass
        except (OSError, asyncio.TimeoutError):
            return None


async def _tls_evidence(host: str, ip: str, port: int) -> List[Evidence]:
    if port not in TLS_PORTS:
        return []
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        def handshake():
            with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT) as raw:
                with context.wrap_socket(raw, server_hostname=host) as sock:
                    cert = sock.getpeercert(binary_form=True)
                    return sock.version() or "Unknown", sock.selected_alpn_protocol() or "Unknown", cert
        tls_version, alpn, cert = await asyncio.to_thread(handshake)
        values = [Evidence(type="tls_version", value=tls_version, source="TLS handshake", confidence=0.98), Evidence(type="alpn", value=alpn, source="TLS handshake", confidence=0.95)]
        if cert:
            digest = hashlib.sha256(cert).hexdigest()
            values.append(Evidence(type="certificate_sha256", value=digest, source="TLS certificate", confidence=1.0))
        return values
    except (OSError, ssl.SSLError):
        return []


def _fingerprint(port: int, data: bytes) -> Tuple[str, str, str, str]:
    text = data.decode("utf-8", errors="ignore")[:1024].replace("\r", " ").replace("\n", " ").strip()
    service = PORT_NAMES.get(port, "Unknown")
    product, version = service, "Unknown"
    if text.startswith("SSH-"):
        service = "SSH"
        match = re.search(r"SSH-[^ ]+-(OpenSSH|dropbear)[_/ -]?([0-9][^ ]*)", text, re.I)
        if match: product, version = match.group(1), match.group(2)
    elif re.match(r"HTTP/\d", text, re.I):
        service = "HTTPS" if port in {443, 8443} else "HTTP"
        match = re.search(r"Server:\s*([^ ]+)", text, re.I)
        if match:
            product = match.group(1)
            vm = re.search(r"([0-9]+(?:\.[0-9]+)+(?:[-_][A-Za-z0-9.-]+)?)", product)
            version = vm.group(1) if vm else "Unknown"
    elif port == 6379 and ("redis" in text.lower() or text.startswith("-ERR")):
        service, product = "Redis", "Redis"
    return service, product, version, text or "No banner"


async def scan_tcp_services(host: str, ip: str, ports: List[int]) -> List[PortService]:
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    results = await asyncio.gather(*[_tcp_probe(ip, port, semaphore) for port in ports])
    services: List[PortService] = []
    for port, data in zip(ports, results):
        if data is None: continue
        service, product, version, banner = _fingerprint(port, data)
        evidence = [Evidence(type="tcp_connect", value=f"{ip}:{port}", source="AetherMap TCP connect", confidence=1.0)]
        if banner != "No banner": evidence.append(Evidence(type="banner", value=banner[:512], source="protocol probe", confidence=0.90))
        evidence.extend(await _tls_evidence(host, ip, port))
        services.append(PortService(host=host, ip=ip, port=port, service_name=service, product=product, version=version, banner=banner, evidence=evidence))
    return services


def _version_tuple(value: str) -> Tuple[int, ...]:
    nums = re.findall(r"\d+", value or "")
    return tuple(int(x) for x in nums[:6]) or (0,)


def _cpe_match(cpe: str, product: str, version: str) -> bool:
    parts = cpe.split(":")
    if len(parts) < 6: return False
    vendor_product = f"{parts[3]}:{parts[4]}".lower()
    keyword = PRODUCT_CPE_KEYWORDS.get(next((k for k in PRODUCT_CPE_KEYWORDS if k in product.lower()), ""), "")
    if not keyword or vendor_product != keyword: return False
    return parts[5] in {version, "*", "-"}


async def _nvd_get(client: httpx.AsyncClient, url: str, params: dict) -> Optional[dict]:
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key: headers["apiKey"] = api_key
    for attempt in range(3):
        try:
            response = await client.get(url, params=params, headers=headers)
            if response.status_code == 429:
                await asyncio.sleep(1.5 * (attempt + 1)); continue
            if response.status_code == 200: return response.json()
            if response.status_code >= 500:
                await asyncio.sleep(0.8 * (attempt + 1)); continue
            return None
        except httpx.HTTPError:
            await asyncio.sleep(0.5 * (attempt + 1))
    return None


async def correlate_nvd(service: PortService, client: httpx.AsyncClient) -> PortService:
    product_key = next((k for k in PRODUCT_CPE_KEYWORDS if k in service.product.lower()), None)
    if not product_key or service.version == "Unknown":
        return service
    data = await _nvd_get(client, "https://services.nvd.nist.gov/rest/json/cpes/2.0", {"keywordSearch": PRODUCT_CPE_KEYWORDS[product_key], "resultsPerPage": 100})
    if not data: return service
    selected = None
    observed = _version_tuple(service.version)
    for item in data.get("products", []):
        cpe = item.get("cpe", {}).get("cpeName", [])
        for entry in cpe:
            name = entry.get("cpeName")
            if name and _cpe_match(name, service.product, service.version):
                selected = name; break
        if selected: break
    if not selected:
        # Keep an explicit unresolved state instead of inventing a CPE.
        service.evidence.append(Evidence(type="cpe_resolution", value="No exact CPE match", source="NVD CPE API", confidence=0.0))
        return service
    parts = selected.split(":")
    if len(parts) >= 6: parts[5] = service.version; selected = ":".join(parts)
    service.cpe = selected
    service.evidence.append(Evidence(type="cpe", value=selected, source="NVD CPE API", confidence=0.92))
    cve_data = await _nvd_get(client, "https://services.nvd.nist.gov/rest/json/cves/2.0", {"cpeName": selected, "resultsPerPage": 100})
    if not cve_data: return service
    vulns = []
    for item in cve_data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        metric_list = metrics.get("cvssMetricV40") or metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2") or []
        metric = metric_list[0] if metric_list else {}
        cvss = metric.get("cvssData", {})
        score = float(cvss.get("baseScore", 0.0) or 0.0)
        severity = SeverityLevel.CRITICAL if score >= 9 else SeverityLevel.HIGH if score >= 7 else SeverityLevel.MEDIUM if score >= 4 else SeverityLevel.LOW if score > 0 else SeverityLevel.INFO
        desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "NVD vulnerability")
        confidence_score = 0.88 if service.banner != "No banner" else 0.65
        vulns.append(Vulnerability(cve_id=cve.get("id", "Unknown"), severity=severity, cvss_score=score, description=desc[:600], service=service.service_name, port=service.port, confidence="high" if confidence_score >= .8 else "medium", confidence_score=confidence_score, source="NVD", evidence=[Evidence(type="version", value=service.version, source="service fingerprint", confidence=confidence_score), Evidence(type="cpe", value=selected, source="NVD CPE API", confidence=.92)]))
    service.vulnerabilities = vulns[:50]
    return service


async def _correlate_all(services: List[PortService]) -> List[PortService]:
    if not services: return []
    async with httpx.AsyncClient(timeout=NVD_TIMEOUT, headers={"User-Agent": f"AetherMap-OSINT/{SCANNER_VERSION}"}) as client:
        # NVD requests are deliberately serialized to respect public API limits.
        output = []
        for service in services:
            output.append(await correlate_nvd(service, client))
            await asyncio.sleep(0.2 if os.getenv("NVD_API_KEY") else 0.7)
        return output


def compute_threat_metrics(services: List[PortService], subdomains: List[Subdomain]) -> Tuple[int, str, VulnerabilitySummary]:
    counts = {level: 0 for level in SeverityLevel}
    for service in services:
        for vuln in service.vulnerabilities: counts[vuln.severity] += 1
    total = sum(counts.values())
    raw = counts[SeverityLevel.CRITICAL]*28 + counts[SeverityLevel.HIGH]*15 + counts[SeverityLevel.MEDIUM]*6 + counts[SeverityLevel.LOW]*2 + len(services)*2 + min(len(subdomains),10)
    score = min(100, max(0, raw))
    risk = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 35 else "LOW" if score else "CLEAN"
    return score, risk, VulnerabilitySummary(critical=counts[SeverityLevel.CRITICAL], high=counts[SeverityLevel.HIGH], medium=counts[SeverityLevel.MEDIUM], low=counts[SeverityLevel.LOW], info=counts[SeverityLevel.INFO], total=total)


async def _scan_asset(sub: Subdomain, ports: List[int]) -> Tuple[Subdomain, List[PortService]]:
    ips = await resolve_host(sub.name)
    if not ips:
        sub.status = "unresolved"; return sub, []
    sub.ip, sub.status, sub.scanned = ips[0], "resolved", True
    return sub, await scan_tcp_services(sub.name, ips[0], ports)


async def orchestrate_recon(domain: str, *, demo_mode: bool = False, ports: Optional[List[int]] = None, max_assets: int = MAX_ASSETS) -> ReconResponse:
    started = time.perf_counter()
    if demo_mode:
        from app.demo_data import demo_services
        services = demo_services()
        timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
        score, risk, summary = compute_threat_metrics(services, [])
        return ReconResponse(target_domain=domain, root_ip="203.0.113.10", timestamp=timestamp, threat_score=score, risk_level=risk, services=services, vulnerability_summary=summary, metadata=ReconMetadata(execution_time_ms=round((time.perf_counter()-started)*1000,2), sources_queried=["Synthetic demo dataset"], findings_mode="demo", scanner_version=SCANNER_VERSION))

    (root_ip, dns_ok), (subdomains, crt_status) = await asyncio.gather(resolve_dns_async(domain), query_crt_sh(domain))
    if not dns_ok:
        response = ReconResponse(target_domain=domain, root_ip="Unknown", timestamp=dt.datetime.now(dt.timezone.utc).isoformat(), threat_score=0, risk_level="CLEAN", subdomains=subdomains, vulnerability_summary=VulnerabilitySummary(), metadata=ReconMetadata(execution_time_ms=round((time.perf_counter()-started)*1000,2), sources_queried=["DNS","Certificate Transparency (crt.sh)"], dns_resolved=False, crt_sh_status=crt_status, findings_mode="passive-active", scan_ports=_ports(ports), scanner_version=SCANNER_VERSION))
        response.metadata.historical_change = _history_save(domain, response)
        return response

    scan_ports = _ports(ports)
    subdomains = subdomains[:max(1, min(max_assets, MAX_ASSETS))]
    if domain not in {s.name for s in subdomains}:
        subdomains.insert(0, Subdomain(name=domain, source="DNS", last_seen=dt.datetime.now(dt.timezone.utc).isoformat()))
        subdomains = subdomains[:max(1, min(max_assets, MAX_ASSETS))]
    scanned = await asyncio.gather(*[_scan_asset(sub, scan_ports) for sub in subdomains])
    all_services: List[PortService] = []
    for sub, services in scanned:
        all_services.extend(services)
    all_services = await _correlate_all(all_services)
    score, risk, summary = compute_threat_metrics(all_services, subdomains)
    response = ReconResponse(target_domain=domain, root_ip=root_ip, timestamp=dt.datetime.now(dt.timezone.utc).isoformat(), threat_score=score, risk_level=risk, subdomains=subdomains, services=all_services, vulnerability_summary=summary, metadata=ReconMetadata(execution_time_ms=round((time.perf_counter()-started)*1000,2), sources_queried=["DNS","Certificate Transparency (crt.sh)","TCP connect scanner","TLS handshake","NVD CPE/CVE API"], dns_resolved=True, crt_sh_status=crt_status, network_intel_status="local TCP scanner", findings_mode="passive-active", scan_ports=scan_ports, open_ports=len(all_services), hosts_scanned=sum(1 for s in subdomains if s.scanned), scanner_version=SCANNER_VERSION))
    response.metadata.historical_change = _history_save(domain, response)
    return response
