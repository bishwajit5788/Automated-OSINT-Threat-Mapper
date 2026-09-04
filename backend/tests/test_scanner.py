from app.engines import _fingerprint, _ports


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
