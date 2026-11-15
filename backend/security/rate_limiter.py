"""
In-Memory Rate Limiting and Client Access Control Module.
Enforces per-IP request throttling to prevent denial of service and API abuse.
Supports optional API Key authentication when configured.
"""
import logging
import time
from collections import defaultdict
from typing import Dict, List
from fastapi import HTTPException, Request, status

from backend.config import API_KEY, RATE_LIMIT_PER_MINUTE

logger = logging.getLogger(__name__)


class InMemoryRateLimiter:
    """
    Sliding-window per-IP rate limiter with automatic historical timestamp expiration.
    """
    def __init__(self, requests_per_minute: int = RATE_LIMIT_PER_MINUTE):
        self.rpm = requests_per_minute
        self._history: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        window_start = now - 60.0

        # Retain only timestamps within the rolling 60-second window
        valid_timestamps = [t for t in self._history[client_ip] if t > window_start]
        self._history[client_ip] = valid_timestamps

        if len(valid_timestamps) >= self.rpm:
            return False

        self._history[client_ip].append(now)
        return True

    def reset(self):
        """Resets all recorded rate limit history (useful in testing)."""
        self._history.clear()


limiter = InMemoryRateLimiter()


def check_rate_limit_and_auth(request: Request):
    """
    FastAPI dependency to enforce API key validation (if configured) and per-IP rate limiting.
    """
    # 1. API Key check if configured
    if API_KEY:
        header_key = request.headers.get("X-API-Key")
        auth_header = request.headers.get("Authorization", "")
        bearer_key = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""
        provided_key = header_key or bearer_key
        if provided_key != API_KEY:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API Key."
            )

    # 2. Extract Client IP
    client_ip = "127.0.0.1"
    if request.client and request.client.host:
        client_ip = request.client.host

    # Check forward headers if behind a proxy
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()

    # 3. Rate Limit evaluation
    if not limiter.is_allowed(client_ip):
        logger.warning(f"Rate limit exceeded for client IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Too many analysis requests submitted. Please wait a moment."
        )

