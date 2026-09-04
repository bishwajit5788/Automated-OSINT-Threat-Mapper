"""Production API authentication and bounded request throttling."""
from __future__ import annotations

import hashlib
import hmac
import os
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Deque

from fastapi import Header, HTTPException, status

_API_KEY = os.getenv("AETHERMAP_API_KEY", "").strip()
_RATE_LIMIT = max(1, min(int(os.getenv("SCAN_RATE_LIMIT", "10")), 60))
_RATE_WINDOW = max(10, min(int(os.getenv("SCAN_RATE_WINDOW_SECONDS", "60")), 3600))
_lock = Lock()
_requests: dict[str, Deque[float]] = defaultdict(deque)


def auth_required() -> bool:
    return bool(_API_KEY)


def require_api_key(x_aethermap_api_key: str | None = Header(default=None, alias="X-AetherMap-API-Key")) -> str:
    """Require the configured API key when AETHERMAP_API_KEY is set."""
    if not _API_KEY:
        return "anonymous-local"
    if not x_aethermap_api_key or not hmac.compare_digest(x_aethermap_api_key, _API_KEY):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Valid AetherMap API key required.", headers={"WWW-Authenticate": "ApiKey"})
    return "api-key"


def check_scan_rate_limit(client_key: str) -> None:
    """Apply a fixed-window rolling limit to active scan requests."""
    now = time.monotonic()
    cutoff = now - _RATE_WINDOW
    with _lock:
        bucket = _requests[client_key]
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= _RATE_LIMIT:
            retry = max(1, int(bucket[0] + _RATE_WINDOW - now))
            raise HTTPException(status_code=429, detail="Scan rate limit exceeded.", headers={"Retry-After": str(retry)})
        bucket.append(now)


def client_key(api_key: str, forwarded_for: str | None, host: str | None) -> str:
    identity = api_key if api_key != "anonymous-local" else (forwarded_for or host or "anonymous")
    return hashlib.sha256(identity.encode()).hexdigest()
