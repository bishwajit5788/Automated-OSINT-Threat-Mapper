from app.engines import _cpe_exact, _cve_applies, _fingerprint, _is_public_ip, _ports, _stable_payload, _web_evidence
from app.schemas import ReconResponse


def test_http_fingerprint_reads_server_version():
    service, product, version, _ = _fingerprint(80, b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n")
    assert service == "HTTP"
    assert product == "nginx/1.24.0"
    assert version == "1.24.0"


def test_ssh_fingerprint_reads_openssh_version():
    service, product, version, _ = _fingerprint(22, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
    assert service == "SSH"
    assert product == "OpenSSH"
    assert version == "9.6p1"


def test_protocol_fingerprints_cover_common_services():
    assert _fingerprint(21, b"220 vsftpd 3.0.5")[0] == "FTP"
    assert _fingerprint(25, b"220 mail.example ESMTP Postfix")[0] == "SMTP"
    assert _fingerprint(6379, b"+PONG")[0] == "Redis"


def test_web_security_headers_and_technology_are_evidence():
    evidence = _web_evidence(b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nX-Powered-By: Express\r\nContent-Security-Policy: default-src 'self'\r\n\r\n<title>Portal</title><div id='__next_data__'>")
    values = [e.value for e in evidence]
    assert any("server:" in v for v in values)
    assert any("content-security-policy: present" in v for v in values)
    assert any(e.value == "Next.js" for e in evidence)


def test_default_port_profile_is_bounded():
    ports = _ports(None)
    assert len(ports) <= 128
    assert 80 in ports and 443 in ports


def test_private_and_reserved_targets_are_blocked():
    assert not _is_public_ip("127.0.0.1")
    assert not _is_public_ip("10.0.0.1")
    assert not _is_public_ip("169.254.169.254")
    assert not _is_public_ip("192.168.1.10")
    assert not _is_public_ip("::1")
    assert not _is_public_ip("fc00::1")
    assert _is_public_ip("8.8.8.8")


def test_cpe_matching_is_product_and_version_specific():
    assert _cpe_exact("cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*", "nginx", "1.24.0")
    assert not _cpe_exact("cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*", "nginx", "1.24.0")


def test_cve_applicability_requires_vulnerable_matching_configuration():
    cve = {"configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "versionEndExcluding": "1.25.0"}]}]}]}
    selected = "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
    assert _cve_applies(cve, selected, "1.24.0")
    assert not _cve_applies(cve, selected, "1.25.0")


def test_history_fingerprint_ignores_volatile_metadata():
    a = ReconResponse(target_domain="example.com", timestamp="2026-01-01T00:00:00Z", threat_score=0, risk_level="CLEAN")
    b = ReconResponse(target_domain="example.com", timestamp="2026-01-02T00:00:00Z", threat_score=0, risk_level="CLEAN")
    assert _stable_payload(a) == _stable_payload(b)
