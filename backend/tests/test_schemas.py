from pydantic import ValidationError
import pytest

from app.schemas import ReconRequest


def test_domain_normalization():
    payload = ReconRequest(domain="https://Example.COM/path")
    assert payload.domain == "example.com"


def test_rejects_invalid_domain():
    with pytest.raises(ValidationError):
        ReconRequest(domain="not a domain")


def test_rejects_ip_literal():
    with pytest.raises(ValidationError):
        ReconRequest(domain="127.0.0.1")
