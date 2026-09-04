from pathlib import Path
import sys

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.schemas import ReconRequest  # noqa: E402


def test_domain_normalization():
    payload = ReconRequest(domain="https://Example.COM/path")
    assert payload.domain == "example.com"


def test_rejects_invalid_domain():
    with pytest.raises(ValidationError):
        ReconRequest(domain="not a domain")


def test_rejects_ip_literal():
    with pytest.raises(ValidationError):
        ReconRequest(domain="127.0.0.1")
