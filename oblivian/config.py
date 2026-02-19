from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass(frozen=True)
class PolicyConfig:
    allowed_roots: List[str]
    blocked_path_patterns: List[str]
    blocked_content_patterns: List[str]
    allow_network: bool
    allowed_domains: List[str]
    max_bytes_read: int
    max_bytes_write: int
    max_http_bytes: int
    allow_shell: bool
    redact_patterns: List[str]
    api_key: Optional[str] = None
    rate_limit_requests: int = 0
    rate_limit_window_seconds: int = 60


DEFAULT_POLICY_PATH = "config/policy.json"


def load_policy(path: str | None = None) -> PolicyConfig:
    policy_path = Path(path or os.getenv("OBLIVIAN_POLICY_PATH", DEFAULT_POLICY_PATH))
    data = json.loads(policy_path.read_text())
    return PolicyConfig(
        allowed_roots=data.get("allowed_roots", []),
        blocked_path_patterns=data.get("blocked_path_patterns", []),
        blocked_content_patterns=data.get("blocked_content_patterns", []),
        allow_network=bool(data.get("allow_network", False)),
        allowed_domains=data.get("allowed_domains", []),
        max_bytes_read=int(data.get("max_bytes_read", 262144)),
        max_bytes_write=int(data.get("max_bytes_write", 262144)),
        max_http_bytes=int(data.get("max_http_bytes", 262144)),
        allow_shell=bool(data.get("allow_shell", False)),
        redact_patterns=data.get("redact_patterns", []),
        api_key=data.get("api_key") or os.getenv("OBLIVIAN_API_KEY") or None,
        rate_limit_requests=int(data.get("rate_limit_requests", 0)),
        rate_limit_window_seconds=int(data.get("rate_limit_window_seconds", 60)),
    )
