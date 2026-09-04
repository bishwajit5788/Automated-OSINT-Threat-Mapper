import importlib

import pytest
from fastapi import HTTPException


def test_rate_limit_rejects_after_configured_window(monkeypatch):
    monkeypatch.setenv("AETHERMAP_API_KEY", "test-key")
    monkeypatch.setenv("SCAN_RATE_LIMIT", "2")
    security = importlib.import_module("app.security")
    importlib.reload(security)
    security.check_scan_rate_limit("client")
    security.check_scan_rate_limit("client")
    with pytest.raises(HTTPException) as exc:
        security.check_scan_rate_limit("client")
    assert exc.value.status_code == 429


def test_api_key_is_required_when_configured(monkeypatch):
    monkeypatch.setenv("AETHERMAP_API_KEY", "secret")
    security = importlib.import_module("app.security")
    importlib.reload(security)
    with pytest.raises(HTTPException) as exc:
        security.require_api_key(None)
    assert exc.value.status_code == 401
    assert security.require_api_key("secret") == "api-key"


def test_confidence_never_exceeds_one_and_rewards_evidence():
    from app.confidence import evidence_confidence
    from app.schemas import Evidence, PortService
    service = PortService(port=443, ip="93.184.216.34", product="nginx", version="1.2.3", evidence=[Evidence(type="banner", value="nginx/1.2.3", source="TCP", confidence=.98)])
    score = evidence_confidence(service)
    assert 0.0 < score <= 1.0
