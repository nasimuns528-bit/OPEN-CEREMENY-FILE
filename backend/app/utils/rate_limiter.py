"""
In-memory sliding-window rate limiter.
Protects sensitive authentication endpoints from brute-force attacks.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List

from fastapi import HTTPException, Request, status


class SlidingWindowRateLimiter:
    """Sliding-window rate limiter per client key (e.g. IP + endpoint)."""

    def __init__(self, max_requests: int = 5, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._history: Dict[str, List[float]] = defaultdict(list)

    def check(self, key: str) -> None:
        """Check if request exceeds limit. Raises HTTP 429 if exceeded."""
        now = time.time()
        window_start = now - self.window_seconds

        # Prune older entries
        self._history[key] = [t for t in self._history[key] if t > window_start]

        if len(self._history[key]) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - self._history[key][0]))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many login attempts. Please try again in {max(retry_after, 1)} seconds.",
                headers={"Retry-After": str(max(retry_after, 1))},
            )

        self._history[key].append(now)

    def reset(self, key: str) -> None:
        """Reset rate-limit history for a key upon successful authentication."""
        self._history.pop(key, None)


# Default login rate limiter: 5 attempts per 60 seconds
login_rate_limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)
