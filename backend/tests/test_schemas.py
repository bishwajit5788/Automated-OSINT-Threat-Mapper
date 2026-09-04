from pathlib import Path
import sys
import pytest
from pydantic import ValidationError
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.schemas import ReconRequest

def test_domain_normalization():
    assert ReconRequest(domain="https://Example.COM/path").domain == "example.com"

def test_rejects_invalid_domain():
    with pytest.raises(ValidationError): ReconRequest(domain="not a domain")

def test_rejects_ip_literal():
    with pytest.raises(ValidationError): ReconRequest(domain="127.0.0.1")

def test_port_profile_is_bounded_and_deduplicated():
    assert ReconRequest(domain="example.com", ports=[443,22,443]).ports == [22,443]

def test_asset_limit_is_bounded():
    with pytest.raises(ValidationError): ReconRequest(domain="example.com", max_assets=101)
