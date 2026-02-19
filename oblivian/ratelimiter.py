from __future__ import annotations

import time
from collections import defaultdict


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._timestamps: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str) -> tuple[bool, int]:
        now = time.time()
        cutoff = now - self._window_seconds
        timestamps = self._timestamps[key]

        # Prune entries outside the window
        self._timestamps[key] = [t for t in timestamps if t > cutoff]
        timestamps = self._timestamps[key]

        if len(timestamps) >= self._max_requests:
            retry_after = int(timestamps[0] + self._window_seconds - now) + 1
            return False, retry_after

        self._timestamps[key].append(now)
        return True, 0
