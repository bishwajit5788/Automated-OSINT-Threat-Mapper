"""Bounded, evidence-first OSINT and active service assessment engine.

Active checks are non-destructive and must only be run against systems the
operator is authorized to assess. The engine deliberately avoids exploitation,
credential attacks, SYN flooding, OS detection and arbitrary URL fetching.
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
import struct
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx

from app.schemas import Evidence, PortService, ReconMetadata, ReconResponse, SeverityLevel, Subdomain, Vulnerability, VulnerabilitySummary

logger = logging.getLogger("aethermap.engines")
SCANNER_VERSION = "3.2.0"
DEFAULT_PORTS = [21,22,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1433,1521,2049,2375,3000,3306,3389,5000,5432,5601,5672,6379,6443,8000,8080,8443,9000,9200,27017]
DEFAULT_UDP_PORTS = [53,123,161,500,4500,5353]
HTTP_PORTS = {80,3000,5000,8000,8080,8443,9000}
TLS_PORTS = {443,465,563,636,853,993,995,8443}
PORT_NAMES = {21:"FTP",22:"SSH",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",111:"RPC",135:"MSRPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",465:"SMTPS",587:"SMTP",993:"IMAPS",995:"POP3S",1433:"MSSQL",1521:"Oracle",2049:"NFS",2375:"Docker",3000:"HTTP",3306:"MySQL",3389:"RDP",5000:"HTTP",5432:"PostgreSQL",5601:"Kibana",5672:"AMQP",6379:"Redis",6443:"Kubernetes API",8000:"HTTP",8080:"HTTP",8443:"HTTPS",9000:"HTTP",9200:"Elasticsearch",27017:"MongoDB"}
PRODUCT_CPE_KEYWORDS = {"openssh":"openbsd:openssh", "apache":"apache:http_server", "nginx":"nginx:nginx", "redis":"redis:redis", "elasticsearch":"elastic:elasticsearch", "mysql":"oracle:mysql", "postgresql":"postgresql:postgresql", "mongodb":"mongodb:mongodb", "tomcat":"apache:tomcat"}
DB_PATH = Path(os.getenv("AETHERMAP_HISTORY_DB", "data/aethermap_history.sqlite3"))
MAX_CONCURRENCY = max(1, min(int(os.getenv("SCAN_CONCURRENCY", "32")), 128))
MAX_ASSETS = max(1, min(int(os.getenv("MAX_ASSETS", "25")), 100))
MAX_IPS_PER_HOST = max(1, min(int(os.getenv("MAX_IPS_PER_HOST", "4")), 8))
CONNECT_TIMEOUT = max(0.25, min(float(os.getenv("SCAN_CONNECT_TIMEOUT", "1.5")), 10.0))
UDP_TIMEOUT = max(0.25, min(float(os.getenv("SCAN_UDP_TIMEOUT", "1.5")), 5.0))
NVD_TIMEOUT = max(2.0, min(float(os.getenv("NVD_TIMEOUT", "10")), 30.0))


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


def _service_key(s: dict) -> Tuple[str, str, int, str]:
    return (s.get("host", ""), s.get("ip", ""), int(s.get("port", 0)), s.get("protocol", "tcp"))


def history_diff(domain: str) -> Dict[str, List]:
    _history_init()
    with sqlite3.connect(DB_PATH) as db:
        rows = db.execute("SELECT payload FROM scans WHERE domain=? ORDER BY id DESC LIMIT 2", (domain,)).fetchall()
    empty = {"added_ports": [], "removed_ports": [], "added_assets": [], "removed_assets": [], "changed_services": [], "added_cves": [], "removed_cves": [], "added_ips": [], "removed_ips": []}
    if len(rows) < 2:
        return empty
    current, previous = json.loads(rows[0][0]), json.loads(rows[1][0])
    now = {_service_key(s): s for s in current.get("services", [])}
    old = {_service_key(s): s for s in previous.get("services", [])}
    changed = []
    for key in sorted(now.keys() & old.keys(), key=str):
        a, b = now[key], old[key]
        av = (a.get("service_name"), a.get("product"), a.get("version"), a.get("cpe"), sorted(v.get("cve_id") for v in a.get("vulnerabilities", [])))
        bv = (b.get("service_name"), b.get("product"), b.get("version"), b.get("cpe"), sorted(v.get("cve_id") for v in b.get("vulnerabilities", [])))
        if av != bv:
            changed.append({"host": key[0], "ip": key[1], "port": key[2], "protocol": key[3], "before": {"product": b.get("product"), "version": b.get("version"), "cpe": b.get("cpe")}, "after": {"product": a.get("product"), "version": a.get("version"), "cpe": a.get("cpe")}})
    now_ports = {(k[2], k[3]) for k in now}; old_ports = {(k[2], k[3]) for k in old}
    now_assets = {s.get("name") for s in current.get("subdomains", [])}; old_assets = {s.get("name") for s in previous.get("subdomains", [])}
    now_ips = {k[1] for k in now if k[1] != "Unknown"}; old_ips = {k[1] for k in old if k[1] != "Unknown"}
    cves_now = {v.get("cve_id") for s in now.values() for v in s.get("vulnerabilities", [])}
    cves_old = {v.get("cve_id") for s in old.values() for v in s.get("vulnerabilities", [])}
    return {"added_ports": sorted(now_ports-old_ports), "removed_ports": sorted(old_ports-now_ports), "added_assets": sorted(now_assets-old_assets), "removed_assets": sorted(old_assets-now_assets), "changed_services": changed, "added_cves": sorted(cves_now-cves_old), "removed_cves": sorted(cves_old-cves_now), "added_ips": sorted(now_ips-old_ips), "removed_ips": sorted(old_ips-now_ips)}


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_global and not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return False


async def resolve_host(host: str) -> List[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except (socket.gaierror, socket.herror, TimeoutError, OSError) as exc:
        logger.warning("DNS resolution failed for %s: %s", host, exc)
        return []
    values = []
    for info in infos:
        ip = info[4][0]
        if _is_public_ip(ip) and ip not in values:
            values.append(ip)
    return values[:MAX_IPS_PER_HOST]


async def resolve_dns_async(domain: str) -> Tuple[str, bool]:
    ips = await resolve_host(domain)
    return (ips[0], True) if ips else ("Unknown", False)


async def query_crt_sh(domain: str, max_assets: int = MAX_ASSETS) -> Tuple[List[Subdomain], str]:
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
    subdomains.sort(key=lambda x: (x.name != domain, x.name))
    return subdomains[:max(1, min(max_assets, MAX_ASSETS))], "Success"


def _ports(requested: Optional[List[int]]) -> List[int]:
    if requested:
        return sorted(set(requested))
    raw = os.getenv("SCAN_PORTS", "")
    if raw:
        try:
            parsed = sorted({int(p.strip()) for p in raw.split(",") if p.strip()})
            if len(parsed) <= 128 and all(1 <= p <= 65535 for p in parsed): return parsed
        except ValueError: pass
    return DEFAULT_PORTS


def _udp_ports() -> List[int]:
    raw = os.getenv("SCAN_UDP_PORTS", "")
    if raw:
        try:
            parsed = sorted({int(p.strip()) for p in raw.split(",") if p.strip()})
            if len(parsed) <= 32 and all(1 <= p <= 65535 for p in parsed): return parsed
        except ValueError: pass
    return DEFAULT_UDP_PORTS


async def _tcp_probe(ip: str, port: int, semaphore: asyncio.Semaphore, host: str) -> Optional[bytes]:
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=CONNECT_TIMEOUT)
            try:
                if port in HTTP_PORTS:
                    writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: AetherMap-Scanner/{SCANNER_VERSION}\r\nConnection: close\r\n\r\n".encode())
                elif port == 22:
                    writer.write(b"\r\n")
                elif port == 25 or port == 587 or port == 465:
                    writer.write(b"EHLO aethermap.local\r\n")
                elif port in (21,):
                    writer.write(b"\r\n")
                elif port == 6379:
                    writer.write(b"*1\r\n$4\r\nPING\r\n")
                await writer.drain()
                return await asyncio.wait_for(reader.read(4096), timeout=1.5)
            finally:
                writer.close()
                try: await writer.wait_closed()
                except Exception: pass
        except (OSError, asyncio.TimeoutError):
            return None


def _version_from_text(text: str) -> str:
    match = re.search(r"(?<!\d)(\d+(?:\.\d+)+(?:[A-Za-z][\w.-]*)?)", text)
    return match.group(1) if match else "Unknown"


def _fingerprint(port: int, data: bytes) -> Tuple[str, str, str, str]:
    text = data.decode("utf-8", errors="ignore")[:2048].replace("\x00", " ").strip()
    lower = text.lower()
    service, product, version = PORT_NAMES.get(port, "Unknown"), PORT_NAMES.get(port, "Unknown"), "Unknown"
    if text.startswith("SSH-"):
        service = "SSH"; m = re.search(r"SSH-[^ -]+-(OpenSSH|dropbear)[_/ -]?([^ ]+)", text, re.I)
        if m: product, version = m.group(1), m.group(2)
    elif re.match(r"HTTP/\d", text, re.I):
        service = "HTTPS" if port in {443,8443} else "HTTP"
        m = re.search(r"(?:^| )Server:\s*([^\r\n ]+)", text, re.I)
        if m:
            product = m.group(1); version = _version_from_text(product)
    elif port in (21,) and text:
        service = "FTP"; product = (re.match(r"([^ ]+)", text) or ["FTP"])[1]; version = _version_from_text(text)
    elif port in (25,465,587) and text:
        service = "SMTP"; m = re.search(r"(?:220|250)[ -].*?([A-Za-z][A-Za-z0-9._-]+(?:/[0-9.]+)?)", text); product = m.group(1) if m else "SMTP"; version = _version_from_text(product)
    elif port == 6379 and ("redis" in lower or lower.startswith("+pong") or lower.startswith("-err")):
        service, product, version = "Redis", "Redis", _version_from_text(text)
    elif port == 3306 and data.startswith(b"\x0a"):
        service, product, version = "MySQL", "MySQL", _version_from_text(text)
    elif port == 5432 and ("postgres" in lower):
        service, product, version = "PostgreSQL", "PostgreSQL", _version_from_text(text)
    elif port == 27017 and ("mongodb" in lower):
        service, product, version = "MongoDB", "MongoDB", _version_from_text(text)
    elif port == 9200 and ("elasticsearch" in lower or '"cluster_name"' in lower):
        service, product, version = "Elasticsearch", "Elasticsearch", _version_from_text(text)
    return service, product, version, text or "No banner"


def _web_evidence(data: bytes) -> List[Evidence]:
    text = data.decode("utf-8", errors="ignore")[:8192]
    lower = text.lower(); out = []
    headers = {}
    for line in text.splitlines():
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1); headers[k.lower().strip()] = v.strip()
    for key in ("server", "x-powered-by", "x-generator", "via"):
        if key in headers: out.append(Evidence(type="http_header", value=f"{key}: {headers[key]}", source="HTTP response", confidence=0.98))
    for key in ("strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy"):
        out.append(Evidence(type="security_header", value=f"{key}: present" if key in headers else f"{key}: missing", source="HTTP response", confidence=0.98))
    title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I|re.S)
    if title: out.append(Evidence(type="web_title", value=re.sub(r"\s+", " ", title.group(1)).strip()[:200], source="HTML", confidence=0.95))
    generator = re.search(r'<meta[^>]+name=[\"\']generator[\"\'][^>]+content=[\"\']([^\"\']+)', text, re.I)
    if generator: out.append(Evidence(type="web_technology", value=generator.group(1)[:200], source="HTML meta generator", confidence=0.92))
    tech = []
    for marker, name in (("wp-content", "WordPress"), ("drupal-settings-json", "Drupal"), ("__next_data__", "Next.js"), ("ng-version", "Angular"), ("reactroot", "React")):
        if marker in lower: tech.append(name)
    for name in sorted(set(tech)): out.append(Evidence(type="web_technology", value=name, source="HTML fingerprint", confidence=0.85))
    return out


async def _tls_evidence(host: str, ip: str, port: int) -> List[Evidence]:
    if port not in TLS_PORTS: return []
    out = []
    def handshake():
        context = ssl.create_default_context(); context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                return sock.version() or "Unknown", sock.cipher(), sock.selected_alpn_protocol() or "Unknown", sock.getpeercert(binary_form=True)
    try:
        tls_version, cipher, alpn, cert = await asyncio.to_thread(handshake)
        out += [Evidence(type="tls_version", value=tls_version, source="TLS handshake", confidence=.99), Evidence(type="tls_cipher", value=str(cipher[0]) if cipher else "Unknown", source="TLS handshake", confidence=.99), Evidence(type="alpn", value=alpn, source="TLS handshake", confidence=.95)]
        if tls_version in {"TLSv1", "TLSv1.1", "SSLv3"}: out.append(Evidence(type="tls_warning", value=f"Deprecated protocol negotiated: {tls_version}", source="TLS handshake", confidence=.99))
        if cipher and any(x in cipher[0].upper() for x in ("RC4", "3DES", "NULL", "EXPORT", "DES-CBC")): out.append(Evidence(type="tls_warning", value=f"Potentially weak cipher: {cipher[0]}", source="TLS handshake", confidence=.97))
        if cert:
            digest = hashlib.sha256(cert).hexdigest(); out.append(Evidence(type="certificate_sha256", value=digest, source="TLS certificate", confidence=1.0))
        return out
    except (OSError, ssl.SSLError):
        return []


async def scan_tcp_services(host: str, ip: str, ports: List[int]) -> List[PortService]:
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    results = await asyncio.gather(*[_tcp_probe(ip, p, semaphore, host) for p in ports])
    services = []
    for port, data in zip(ports, results):
        if data is None: continue
        service, product, version, banner = _fingerprint(port, data)
        evidence = [Evidence(type="tcp_connect", value=f"{ip}:{port}", source="AetherMap TCP connect", confidence=1.0)]
        if banner != "No banner": evidence.append(Evidence(type="banner", value=banner[:512], source="protocol probe", confidence=.90))
        if port in HTTP_PORTS: evidence.extend(_web_evidence(data))
        evidence.extend(await _tls_evidence(host, ip, port))
        services.append(PortService(host=host, ip=ip, port=port, protocol="tcp", service_name=service, product=product, version=version, banner=banner, evidence=evidence))
    return services


def _dns_probe() -> bytes:
    # Query A for the scanned hostname; no recursion or zone transfer.
    tid = os.urandom(2); flags = b"\x01\x00"; qd = b"\x00\x01"; hdr = tid + flags + qd + b"\x00\x00\x00\x00\x00\x00"
    labels = b"".join(bytes([len(x)]) + x.encode() for x in os.getenv("AETHERMAP_DNS_NAME", "example.com").split(".")) + b"\x00"
    return hdr + labels + struct.pack("!HH", 1, 1)


async def _udp_probe(host: str, ip: str, port: int) -> Optional[bytes]:
    payload = _dns_probe() if port == 53 else (b"\x1b" + b"\x00" * 47 if port == 123 else b"\x00")
    loop = asyncio.get_running_loop()
    def exchange():
        sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_DGRAM); sock.settimeout(UDP_TIMEOUT)
        try:
            sock.sendto(payload, (ip, port)); return sock.recv(4096)
        except OSError: return None
        finally: sock.close()
    return await loop.run_in_executor(None, exchange)


async def scan_udp_services(host: str, ip: str, ports: List[int]) -> List[PortService]:
    if ":" in ip: return []
    results = await asyncio.gather(*[_udp_probe(host, ip, p) for p in ports])
    out = []
    for port, data in zip(ports, results):
        if data is None: continue
        service = {53:"DNS",123:"NTP",161:"SNMP",500:"IKE",4500:"IPsec NAT-T",5353:"mDNS"}.get(port, "UDP")
        out.append(PortService(host=host, ip=ip, port=port, protocol="udp", service_name=service, product=service, version="Unknown", banner=data[:256].hex(), evidence=[Evidence(type="udp_response", value=f"{ip}:{port}", source="AetherMap UDP probe", confidence=.80)]))
    return out


def _version_tuple(value: str) -> Tuple[int, ...]:
    nums = re.findall(r"\d+", value or "")
    return tuple(int(x) for x in nums[:8]) or (0,)


def _cpe_exact(cpe: str, product: str, version: str) -> bool:
    parts = cpe.split(":")
    if len(parts) < 6: return False
    keyword = next((PRODUCT_CPE_KEYWORDS[k] for k in PRODUCT_CPE_KEYWORDS if k in product.lower()), None)
    if not keyword or f"{parts[3]}:{parts[4]}".lower() != keyword: return False
    return parts[5] in {version, "*", "-"}


def _cve_applies(cve: dict, selected_cpe: str, observed_version: str) -> bool:
    configs = cve.get("configurations", [])
    if not configs: return False
    observed = _version_tuple(observed_version)
    found = False
    def walk(node: dict) -> bool:
        nonlocal found
        for match in node.get("cpeMatch", []) or []:
            if match.get("vulnerable") is False: continue
            criteria = match.get("criteria") or match.get("cpe22Uri") or ""
            same_product = criteria.split(":")[:5] == selected_cpe.split(":")[:5]
            if not same_product: continue
            version = criteria.split(":")[5] if len(criteria.split(":")) > 5 else "*"
            exact = version in {"*", "-", observed_version}
            lo = match.get("versionStartIncluding"); hi = match.get("versionEndIncluding"); loe = match.get("versionStartExcluding"); hie = match.get("versionEndExcluding")
            if exact or lo or hi or loe or hie:
                if lo and observed < _version_tuple(lo): continue
                if hi and observed > _version_tuple(hi): continue
                if loe and observed <= _version_tuple(loe): continue
                if hie and observed >= _version_tuple(hie): continue
                return True
        for child in node.get("children", []) or []:
            if walk(child): return True
        return False
    for cfg in configs:
        if walk(cfg): found = True; break
    return found


async def _nvd_get(client: httpx.AsyncClient, url: str, params: dict) -> Optional[dict]:
    headers = {"User-Agent": f"AetherMap-OSINT/{SCANNER_VERSION}"}
    if os.getenv("NVD_API_KEY"): headers["apiKey"] = os.getenv("NVD_API_KEY")
    for attempt in range(4):
        try:
            response = await client.get(url, params=params, headers=headers)
            if response.status_code == 429:
                await asyncio.sleep(1.5 * (attempt + 1)); continue
            if response.status_code == 200: return response.json()
            if response.status_code >= 500:
                await asyncio.sleep(.8 * (attempt + 1)); continue
            return None
        except httpx.HTTPError:
            await asyncio.sleep(.5 * (attempt + 1))
    return None


async def correlate_nvd(service: PortService, client: httpx.AsyncClient) -> PortService:
    product_key = next((k for k in PRODUCT_CPE_KEYWORDS if k in service.product.lower()), None)
    if not product_key or service.version == "Unknown":
        return service
    cpe_data = await _nvd_get(client, "https://services.nvd.nist.gov/rest/json/cpes/2.0", {"keywordSearch": PRODUCT_CPE_KEYWORDS[product_key], "resultsPerPage": 100})
    if not cpe_data: return service
    selected = None
    for item in cpe_data.get("products", []):
        for entry in item.get("cpe", {}).get("cpeName", []):
            name = entry.get("cpeName")
            if name and _cpe_exact(name, service.product, service.version): selected = name; break
        if selected: break
    if not selected:
        service.evidence.append(Evidence(type="cpe_resolution", value="unresolved", source="NVD CPE API", confidence=0.0)); return service
    service.cpe = selected
    service.evidence.append(Evidence(type="cpe", value=selected, source="NVD CPE API", confidence=.97))
    cve_data = await _nvd_get(client, "https://services.nist.gov/rest/json/cves/2.0", {"cpeName": selected, "resultsPerPage": 100})
    if not cve_data:
        # Correct NVD endpoint fallback for environments where the first host is unavailable.
        cve_data = await _nvd_get(client, "https://services.nvd.nist.gov/rest/json/cves/2.0", {"cpeName": selected, "resultsPerPage": 100})
    if not cve_data: return service
    vulns = []
    for item in cve_data.get("vulnerabilities", []):
        cve = item.get("cve", {}); cve_id = cve.get("id", "Unknown")
        if not _cve_applies(cve, selected, service.version): continue
        metrics = cve.get("metrics", {}); metric_list = metrics.get("cvssMetricV40") or metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2") or []
        cvss = (metric_list[0] if metric_list else {}).get("cvssData", {}); score = float(cvss.get("baseScore", 0.0) or 0.0)
        severity = SeverityLevel.CRITICAL if score >= 9 else SeverityLevel.HIGH if score >= 7 else SeverityLevel.MEDIUM if score >= 4 else SeverityLevel.LOW if score > 0 else SeverityLevel.INFO
        desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "NVD vulnerability")
        confidence = .96 if service.banner != "No banner" else .88
        vulns.append(Vulnerability(cve_id=cve_id, severity=severity, cvss_score=score, description=desc[:600], service=service.service_name, port=service.port, confidence="high", confidence_score=confidence, source="NVD applicability", evidence=[Evidence(type="version", value=service.version, source="service fingerprint", confidence=confidence), Evidence(type="cpe", value=selected, source="NVD CPE API", confidence=.97), Evidence(type="applicability", value="NVD vulnerable CPE configuration matched observed version", source="NVD CVE API", confidence=.96)]))
    service.vulnerabilities = vulns[:50]
    return service


async def _correlate_all(services: List[PortService]) -> List[PortService]:
    if not services: return []
    async with httpx.AsyncClient(timeout=NVD_TIMEOUT, follow_redirects=False) as client:
        output = []
        for service in services:
            output.append(await correlate_nvd(service, client))
            await asyncio.sleep(.15 if os.getenv("NVD_API_KEY") else .6)
        return output


def compute_threat_metrics(services: List[PortService], subdomains: List[Subdomain]) -> Tuple[int, str, VulnerabilitySummary]:
    counts = {level: 0 for level in SeverityLevel}
    for service in services:
        for vuln in service.vulnerabilities: counts[vuln.severity] += 1
    total = sum(counts.values())
    raw = counts[SeverityLevel.CRITICAL]*28 + counts[SeverityLevel.HIGH]*15 + counts[SeverityLevel.MEDIUM]*6 + counts[SeverityLevel.LOW]*2 + len(services)*2 + min(len(subdomains),10)
    score = min(100, max(0, raw)); risk = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 35 else "LOW" if score else "CLEAN"
    return score, risk, VulnerabilitySummary(critical=counts[SeverityLevel.CRITICAL], high=counts[SeverityLevel.HIGH], medium=counts[SeverityLevel.MEDIUM], low=counts[SeverityLevel.LOW], info=counts[SeverityLevel.INFO], total=total)


async def _scan_asset(sub: Subdomain, ports: List[int], udp_ports: List[int]) -> Tuple[Subdomain, List[PortService]]:
    ips = await resolve_host(sub.name)
    if not ips:
        sub.status = "unresolved"; return sub, []
    sub.ip, sub.status, sub.scanned = ips[0], "resolved", True
    services = []
    for ip in ips:
        tcp, udp = await asyncio.gather(scan_tcp_services(sub.name, ip, ports), scan_udp_services(sub.name, ip, udp_ports))
        services.extend(tcp); services.extend(udp)
        for service in services:
            if service.ip == ip: continue
    return sub, services


async def orchestrate_recon(domain: str, *, demo_mode: bool = False, ports: Optional[List[int]] = None, max_assets: int = MAX_ASSETS) -> ReconResponse:
    started = time.perf_counter()
    if demo_mode:
        from app.demo_data import demo_services
        services = demo_services(); timestamp = dt.datetime.now(dt.timezone.utc).isoformat(); score, risk, summary = compute_threat_metrics(services, [])
        return ReconResponse(target_domain=domain, root_ip="203.0.113.10", timestamp=timestamp, threat_score=score, risk_level=risk, services=services, vulnerability_summary=summary, metadata=ReconMetadata(execution_time_ms=round((time.perf_counter()-started)*1000,2), sources_queried=["Synthetic demo dataset"], findings_mode="demo", scanner_version=SCANNER_VERSION))
    (root_ip, dns_ok), (subdomains, crt_status) = await asyncio.gather(resolve_dns_async(domain), query_crt_sh(domain, max_assets=max_assets))
    scan_ports = _ports(ports); udp_ports = _udp_ports()
    if not dns_ok:
        response = ReconResponse(target_domain=domain, root_ip="Unknown", timestamp=dt.datetime.now(dt.timezone.utc).isoformat(), threat_score=0, risk_level="CLEAN", subdomains=subdomains, vulnerability_summary=VulnerabilitySummary(), metadata=ReconMetadata(execution_time_ms=round((time.perf_counter()-started)*1000,2), sources_queried=["DNS","Certificate Transparency (crt.sh)"], dns_resolved=False, crt_sh_status=crt_status, findings_mode="passive-active", scan_ports=scan_ports, scanner_version=SCANNER_VERSION))
        response.metadata.historical_change = _history_save(domain, response); return response
    subdomains = subdomains[:max(1, min(max_assets, MAX_ASSETS))]
    if domain not in {s.name for s in subdomains}:
        subdomains.insert(0, Subdomain(name=domain, source="DNS", last_seen=dt.datetime.now(dt.timezone.utc).isoformat())); subdomains = subdomains[:max(1, min(max_assets, MAX_ASSETS))]
    scanned = await asyncio.gather(*[_scan_asset(sub, scan_ports, udp_ports) for sub in subdomains])
    all_services = [svc for _, services in scanned for svc in services]
    all_services = await _correlate_all(all_services)
    score, risk, summary = compute_threat_metrics(all_services, subdomains)
    response = ReconResponse(target_domain=domain, root_ip=root_ip, timestamp=dt.datetime.now(dt.timezone.utc).isoformat(), threat_score=score, risk_level=risk, subdomains=subdomains, services=all_services, vulnerability_summary=summary, metadata=ReconMetadata(execution_time_ms=round((time.perf_counter()-started)*1000,2), sources_queried=["DNS","Certificate Transparency (crt.sh)","TCP connect scanner","UDP probes","TLS handshake","HTTP technology/security-header checks","NVD CPE/CVE applicability"], dns_resolved=True, crt_sh_status=crt_status, network_intel_status="local bounded TCP/UDP scanner", findings_mode="passive-active", scan_ports=scan_ports, open_ports=len(all_services), hosts_scanned=sum(1 for s in subdomains if s.scanned), scanner_version=SCANNER_VERSION))
    response.metadata.historical_change = _history_save(domain, response); return response
