from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.tls_assessment import _parse_certificate, assess_tls


def _certificate(common_name="example.com", days=-1, san=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(x) for x in (san or [common_name])]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_certificate_metadata_contains_subject_san_validity_and_rsa_key():
    parsed = _parse_certificate(_certificate(days=180))
    assert "CN=example.com" in parsed["subject"]
    assert parsed["san"] == ["example.com"]
    assert parsed["key_type"] == "RSA"
    assert parsed["key_bits"] == 2048
    assert parsed["signature_algorithm"] == "sha256"
    assert parsed["days_remaining"] > 179
    assert parsed["not_before"] and parsed["not_after"]
    assert parsed["self_signed"] is True


def test_tls_assessment_reports_expired_certificate_and_hostname_mismatch(monkeypatch):
    der = _certificate(common_name="wrong.example.com", days=-1, san=["wrong.example.com"])

    def fake_handshake(host, ip, port, version=None, cipher=None, verify=False):
        if verify:
            raise __import__("ssl").SSLCertVerificationError(62, "Hostname mismatch")
        return "TLSv1.3", ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256), "h2", der

    monkeypatch.setattr("app.tls_assessment._handshake", fake_handshake)
    monkeypatch.setattr("app.tls_assessment._probe_protocol", lambda *args: ("supported", f"{args[3]} accepted"))
    monkeypatch.setattr("app.tls_assessment._enumerate_tls12", lambda *args: (["ECDHE-RSA-AES256-GCM-SHA384"], []))
    monkeypatch.setattr("app.tls_assessment._enumerate_tls13", lambda *args: (["TLS_AES_256_GCM_SHA384"], [], True))

    result, evidence = assess_tls("example.com", "8.8.8.8", 443)
    ids = {item["id"] for item in result["findings"]}
    assert "TLS_CERT_EXPIRED" in ids
    assert "TLS_HOSTNAME_MISMATCH" in ids
    assert result["grade"] in {"C", "D", "F"}
    assert any(e.type == "certificate_san" for e in evidence)
    assert any(e.type == "tls_remediation" for e in evidence)


def test_tls_assessment_reports_weak_cipher(monkeypatch):
    der = _certificate(days=180)

    monkeypatch.setattr("app.tls_assessment._handshake", lambda *args, **kwargs: ("TLSv1.2", ("DES-CBC3-SHA", "TLSv1.2", 112), "Unknown", der))
    monkeypatch.setattr("app.tls_assessment._probe_protocol", lambda *args: ("rejected" if args[3] == "TLSv1.3" else "supported", f"{args[3]} result"))
    monkeypatch.setattr("app.tls_assessment._enumerate_tls12", lambda *args: (["DES-CBC3-SHA"], ["DES-CBC3-SHA"]))
    monkeypatch.setattr("app.tls_assessment._enumerate_tls13", lambda *args: ([], [], True))

    result, _ = assess_tls("example.com", "8.8.8.8", 443)
    assert "DES-CBC3-SHA" in result["weak_ciphers"]
    assert any(f["id"] == "TLS_WEAK_CIPHER" for f in result["findings"])
