from app.engines import _fingerprint, _is_public_ip, _ports, _stable_payload
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


def test_default_port_profile_is_bounded():
    ports = _ports(None)
    assert len(ports) <= 128
    assert 80 in ports and 443 in ports


def test_private_and_reserved_targets_are_blocked():
    assert not _is_public_ip("127.0.0.1")
    assert not _is_public_ip("10.0.0.1")
    assert not _is_public_ip("169.254.169.254")
    assert not _is_public_ip("192.168.1.10")
    assert _is_public_ip("8.8.8.8")


def test_history_fingerprint_ignores_volatile_metadata():
    a = ReconResponse(target_domain="example.com", timestamp="2026-01-01T00:00:00Z", threat_score=0, risk_level="CLEAN")
    b = ReconResponse(target_domain="example.com", timestamp="2026-01-02T00:00:00Z", threat_score=0, risk_level="CLEAN")
    assert _stable_payload(a) == _stable_payload(b)
