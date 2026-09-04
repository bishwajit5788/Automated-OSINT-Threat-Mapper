"""Bounded TLS security assessment for authorized AetherMap scans.

The assessor performs non-destructive TLS handshakes only. It never sends
application payloads and keeps protocol/cipher probes bounded.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from app.schemas import Evidence, PortService

TLS_PORTS = {443, 465, 563, 636, 853, 993, 995, 8443}
PROTOCOLS = (
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
)
TLS13_CIPHERS = (
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
)
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5", "ANULL", "ADH")
LEGACY_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3"}


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def _hostname_matches(host: str, sans: List[str], subject: str) -> bool:
    names = [x.strip().lower() for x in sans if x.strip()]
    if not names and subject:
        names = [x.strip().lower() for x in re.findall(r"CN=([^,]+)", subject, re.I)]
    try:
        return any(ssl.match_hostname({"subjectAltName": [("DNS", n)]}, host) is None for n in names)
    except (ssl.CertificateError, ValueError):
        return False


def _parse_certificate(der: bytes) -> Dict[str, object]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.hazmat.primitives.serialization import Encoding
        cert = x509.load_der_x509_certificate(der)
        sans: List[str] = []
        try:
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        days_remaining = (not_after - now).total_seconds() / 86400
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            key_type, key_bits, curve = "RSA", key.key_size, "Unknown"
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key_type, key_bits, curve = "EC", key.key_size, key.curve.name
        else:
            key_type, key_bits, curve = type(key).__name__, getattr(key, "key_size", 0), "Unknown"
        return {
            "subject": subject, "issuer": issuer, "san": list(sans),
            "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
            "days_remaining": round(days_remaining, 1), "serial": str(cert.serial_number),
            "signature_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown",
            "key_type": key_type, "key_bits": int(key_bits or 0), "curve": curve,
            "sha256": hashlib.sha256(der).hexdigest(),
            "self_signed": subject == issuer,
            "der": der,
        }
    except Exception:
        return {"sha256": hashlib.sha256(der).hexdigest(), "der": der}


def _handshake(host: str, ip: str, port: int, version: Optional[ssl.TLSVersion] = None, cipher: Optional[str] = None, verify: bool = False):
    context = ssl.create_default_context()
    context.check_hostname = verify
    context.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE
    if version is not None:
        context.minimum_version = version
        context.maximum_version = version
    if cipher:
        context.set_ciphers(cipher)
    with socket.create_connection((ip, port), timeout=4.0) as raw:
        with context.wrap_socket(raw, server_hostname=host) as sock:
            return sock.version(), sock.cipher(), sock.selected_alpn_protocol(), sock.getpeercert(binary_form=True)


def _legacy_handshake(host: str, ip: str, port: int, version: ssl.TLSVersion):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    context.minimum_version = version
    context.maximum_version = version
    with socket.create_connection((ip, port), timeout=4.0) as raw:
        with context.wrap_socket(raw, server_hostname=host) as sock:
            return sock.version(), sock.cipher()


def _probe_protocol(host: str, ip: str, port: int, label: str, version: ssl.TLSVersion) -> Tuple[str, str]:
    try:
        negotiated, cipher, _, _ = _handshake(host, ip, port, version=version)
        return "supported", f"{label} accepted; negotiated {negotiated or label} ({cipher[0] if cipher else 'Unknown'})"
    except ssl.SSLError as exc:
        if label in {"TLSv1", "TLSv1.1"}:
            try:
                negotiated, cipher = _legacy_handshake(host, ip, port, version)
                return "supported", f"{label} accepted; negotiated {negotiated or label} ({cipher[0] if cipher else 'Unknown'})"
            except ssl.SSLError as legacy_exc:
                return "rejected", f"{label} rejected ({type(legacy_exc).__name__})"
        return "rejected", f"{label} rejected ({type(exc).__name__})"
    except (OSError, TimeoutError):
        return "inconclusive", f"{label} probe timed out or connection failed"


def _enumerate_tls12(host: str, ip: str, port: int) -> Tuple[List[str], List[str]]:
    base = ssl.create_default_context()
    names = [c["name"] for c in base.get_ciphers() if "TLS_AES" not in c["name"] and "TLS_CHACHA20" not in c["name"]]
    supported: List[str] = []
    weak: List[str] = []
    for name in names[:64]:
        try:
            _, cipher, _, _ = _handshake(host, ip, port, version=ssl.TLSVersion.TLSv1_2, cipher=name)
            if cipher:
                actual = cipher[0]
                if actual not in supported:
                    supported.append(actual)
                    if any(marker in actual.upper() for marker in WEAK_CIPHER_MARKERS):
                        weak.append(actual)
        except (ssl.SSLError, OSError, TimeoutError):
            continue
    return supported, weak


def _enumerate_tls13(host: str, ip: str, port: int) -> Tuple[List[str], List[str], bool]:
    """Probe the bounded IANA TLS 1.3 suite set when OpenSSL CLI is available."""
    openssl = "openssl"
    supported: List[str] = []
    weak: List[str] = []
    for name in TLS13_CIPHERS:
        try:
            target = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
            proc = subprocess.run(
                [openssl, "s_client", "-connect", target, "-servername", host,
                 "-tls1_3", "-ciphersuites", name, "-brief", "-ign_eof"],
                input=b"", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=5.0, check=False,
            )
            text = proc.stdout.decode("utf-8", errors="ignore")
            if proc.returncode == 0 and ("Protocol version: TLSv1.3" in text or "Ciphersuite:" in text):
                supported.append(name)
        except (FileNotFoundError, subprocess.SubprocessError, OSError):
            return supported, weak, False
    return supported, weak, True


def _remediations(findings: List[Dict[str, str]]) -> Dict[str, str]:
    return {
        "TLS_LEGACY_PROTOCOL": "Disable TLS 1.0/1.1 and require TLS 1.2 or TLS 1.3.",
        "TLS_WEAK_CIPHER": "Disable legacy/weak cipher suites and prefer AEAD suites with forward secrecy.",
        "TLS_CERT_EXPIRED": "Renew the certificate and deploy a currently valid certificate chain.",
        "TLS_CERT_EXPIRING": "Renew the certificate before expiry; automate certificate renewal where possible.",
        "TLS_HOSTNAME_MISMATCH": "Install a certificate whose SAN contains the scanned hostname.",
        "TLS_UNTRUSTED_CHAIN": "Install the complete certificate chain from a trusted public CA.",
        "TLS_SELF_SIGNED": "Use a trusted CA certificate for publicly reachable services.",
        "TLS_WEAK_KEY": "Use RSA >= 2048 bits or a modern elliptic-curve public key.",
        "TLS_WEAK_SIGNATURE": "Replace certificates signed with deprecated SHA-1/MD5 algorithms.",
        "TLS_NO_MODERN_PROTOCOL": "Enable TLS 1.2 and/or TLS 1.3 with a current supported server configuration.",
    }


def assess_tls(host: str, ip: str, port: int) -> Tuple[Dict[str, object], List[Evidence]]:
    evidence: List[Evidence] = []
    result: Dict[str, object] = {
        "score": 100, "grade": "A", "supported_protocols": [], "rejected_protocols": [],
        "inconclusive_protocols": [], "supported_ciphers": [], "weak_ciphers": [],
        "certificate": {}, "findings": [], "remediations": [], "cipher_enumeration_complete": False,
    }
    try:
        negotiated, cipher, alpn, der = _handshake(host, ip, port)
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        result["score"] = 0; result["grade"] = "F"; result["findings"] = [{"id": "TLS_UNREACHABLE", "severity": "INFO", "detail": f"TLS handshake unavailable: {type(exc).__name__}"}]
        return result, evidence

    if negotiated:
        evidence.append(Evidence(type="tls_version", value=negotiated, source="TLS handshake", confidence=.99))
    if cipher:
        evidence.append(Evidence(type="tls_cipher", value=cipher[0], source="TLS handshake", confidence=.99))
    evidence.append(Evidence(type="alpn", value=alpn or "Unknown", source="TLS handshake", confidence=.95))

    cert = _parse_certificate(der) if der else {}
    result["certificate"] = {k: v for k, v in cert.items() if k != "der"}
    if cert.get("sha256"):
        evidence.append(Evidence(type="certificate_sha256", value=str(cert["sha256"]), source="TLS certificate", confidence=1.0))
    for key, etype in (("subject", "certificate_subject"), ("issuer", "certificate_issuer"), ("not_before", "certificate_not_before"), ("not_after", "certificate_not_after"), ("days_remaining", "certificate_days_remaining"), ("key_type", "certificate_key_type"), ("key_bits", "certificate_key_bits"), ("curve", "certificate_curve"), ("signature_algorithm", "certificate_signature_algorithm")):
        if key in cert: evidence.append(Evidence(type=etype, value=str(cert[key]), source="TLS certificate", confidence=1.0))
    if cert.get("san"):
        evidence.append(Evidence(type="certificate_san", value=", ".join(cert["san"]), source="TLS certificate", confidence=1.0))

    findings: List[Dict[str, str]] = []
    protocols = result["supported_protocols"]
    for label, version in PROTOCOLS:
        status, detail = _probe_protocol(host, ip, port, label, version)
        if status == "supported": protocols.append(label)
        elif status == "rejected": result["rejected_protocols"].append(label)
        else: result["inconclusive_protocols"].append(label)
        evidence.append(Evidence(type="tls_protocol_probe", value=detail, source="bounded TLS version probe", confidence=.92 if status != "inconclusive" else .55))
        if status == "supported" and label in LEGACY_PROTOCOLS:
            findings.append({"id": "TLS_LEGACY_PROTOCOL", "severity": "HIGH", "detail": f"{label} is accepted by the service."})

    tls12, weak12 = _enumerate_tls12(host, ip, port)
    tls13, weak13, tls13_complete = _enumerate_tls13(host, ip, port)
    result["supported_ciphers"] = sorted(set(tls12 + tls13))
    result["weak_ciphers"] = sorted(set(weak12 + weak13))
    result["cipher_enumeration_complete"] = bool(tls13_complete)
    for name in result["supported_ciphers"]:
        evidence.append(Evidence(type="tls_supported_cipher", value=name, source="bounded cipher probe", confidence=.94))
    for name in result["weak_ciphers"]:
        findings.append({"id": "TLS_WEAK_CIPHER", "severity": "HIGH", "detail": f"Weak cipher accepted: {name}"})
    if not tls13_complete:
        evidence.append(Evidence(type="tls_cipher_enumeration", value="TLS 1.3 enumeration unavailable on this host; TLS 1.2 suites were probed.", source="AetherMap TLS assessor", confidence=.70))

    days = cert.get("days_remaining")
    if isinstance(days, (int, float)):
        if days < 0: findings.append({"id": "TLS_CERT_EXPIRED", "severity": "CRITICAL", "detail": f"Certificate expired {abs(days):.1f} days ago."})
        elif days <= 7: findings.append({"id": "TLS_CERT_EXPIRING", "severity": "HIGH", "detail": f"Certificate expires in {days:.1f} days."})
        elif days <= 30: findings.append({"id": "TLS_CERT_EXPIRING", "severity": "MEDIUM", "detail": f"Certificate expires in {days:.1f} days."})
        elif days <= 90: findings.append({"id": "TLS_CERT_EXPIRING", "severity": "LOW", "detail": f"Certificate expires in {days:.1f} days."})
    sans = cert.get("san", [])
    if sans and not _hostname_matches(host, sans, str(cert.get("subject", ""))):
        findings.append({"id": "TLS_HOSTNAME_MISMATCH", "severity": "HIGH", "detail": f"Certificate SAN does not match {host}."})
    if cert.get("self_signed"):
        findings.append({"id": "TLS_SELF_SIGNED", "severity": "MEDIUM", "detail": "Certificate issuer equals subject; certificate is self-signed."})
    key_bits = int(cert.get("key_bits", 0) or 0)
    if cert.get("key_type") == "RSA" and key_bits and key_bits < 2048:
        findings.append({"id": "TLS_WEAK_KEY", "severity": "HIGH", "detail": f"RSA key size is only {key_bits} bits."})
    if str(cert.get("signature_algorithm", "")).lower() in {"sha1", "md5"}:
        findings.append({"id": "TLS_WEAK_SIGNATURE", "severity": "HIGH", "detail": f"Certificate uses {cert['signature_algorithm']} signature hashing."})
    if not any(p in protocols for p in ("TLSv1.2", "TLSv1.3")):
        findings.append({"id": "TLS_NO_MODERN_PROTOCOL", "severity": "HIGH", "detail": "No modern TLS 1.2/1.3 protocol was accepted."})

    # Trust/hostname validation is deliberately a separate connection because the
    # first connection disables verification so that bad certificates remain inspectable.
    try:
        _handshake(host, ip, port, verify=True)
        evidence.append(Evidence(type="certificate_chain", value="trusted and hostname-validated", source="system trust store", confidence=.99))
    except ssl.SSLCertVerificationError as exc:
        evidence.append(Evidence(type="certificate_chain", value=f"verification failed: {exc.verify_message}", source="system trust store", confidence=.99))
        if "hostname" not in str(exc).lower() and not any(f["id"] == "TLS_HOSTNAME_MISMATCH" for f in findings):
            findings.append({"id": "TLS_UNTRUSTED_CHAIN", "severity": "HIGH", "detail": f"Certificate chain is not trusted: {exc.verify_message}."})
        elif "hostname" in str(exc).lower() and not any(f["id"] == "TLS_HOSTNAME_MISMATCH" for f in findings):
            findings.append({"id": "TLS_HOSTNAME_MISMATCH", "severity": "HIGH", "detail": "Certificate hostname validation failed."})
    except (OSError, ssl.SSLError) as exc:
        evidence.append(Evidence(type="certificate_chain", value=f"verification inconclusive: {type(exc).__name__}", source="system trust store", confidence=.55))

    deductions = {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 3, "INFO": 0}
    score = max(0, min(100, 100 - sum(deductions.get(f["severity"], 0) for f in findings)))
    result["score"] = score; result["grade"] = _grade(score); result["findings"] = findings
    remap = _remediations(findings)
    result["remediations"] = [{"id": f["id"], "action": remap.get(f["id"], "Review the TLS configuration and vendor guidance.")} for f in findings]
    for f in findings:
        evidence.append(Evidence(type="tls_finding", value=f"{f['id']}: {f['detail']}", source="AetherMap TLS risk engine", confidence=.96))
        evidence.append(Evidence(type="tls_remediation", value=remap.get(f["id"], "Review the TLS configuration and vendor guidance."), source="AetherMap TLS risk engine", confidence=.90))
    return result, evidence


async def assess_services_tls(services: List[PortService]) -> List[PortService]:
    targets = [s for s in services if s.protocol == "tcp" and s.port in TLS_PORTS and s.ip not in {"Unknown", ""}]
    if not targets:
        return services
    sem = asyncio.Semaphore(4)
    async def one(service: PortService) -> None:
        async with sem:
            assessment, evidence = await asyncio.to_thread(assess_tls, service.host, service.ip, service.port)
            service.tls_score = int(assessment["score"])
            service.tls_grade = str(assessment["grade"])
            service.tls_supported_protocols = list(assessment["supported_protocols"])
            service.tls_supported_ciphers = list(assessment["supported_ciphers"])
            service.tls_weak_ciphers = list(assessment["weak_ciphers"])
            service.tls_certificate = assessment["certificate"]
            service.tls_findings = assessment["findings"]
            service.tls_remediations = assessment["remediations"]
            service.tls_cipher_enumeration_complete = bool(assessment["cipher_enumeration_complete"])
            service.evidence.extend(evidence)
    await asyncio.gather(*(one(s) for s in targets))
    return services
