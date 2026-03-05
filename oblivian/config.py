from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Dict, List, Optional


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
    scan_block_severity: str = "high"
    audit_max_bytes: int = 5_000_000
    audit_max_files: int = 5
    jwt_secret: Optional[str] = None
    jwt_issuer: Optional[str] = None
    jwt_audience: Optional[str] = None
    agent_policies: Dict[str, Dict] = None
    alert_webhook_url: Optional[str] = None
    alert_webhook_timeout_seconds: int = 5
    alert_severity: str = "denied"
    api_key: Optional[str] = None
    rate_limit_requests: int = 0
    rate_limit_window_seconds: int = 60


DEFAULT_POLICY_PATH = "config/policy.json"


def load_policy(path: str | None = None) -> PolicyConfig:
    policy_path = Path(path or os.getenv("OBLIVIAN_POLICY_PATH", DEFAULT_POLICY_PATH))
    data = json.loads(policy_path.read_text())
    base = policy_path.parent
    raw_roots = data.get("allowed_roots", [])
    allowed_roots: List[str] = []
    for root in raw_roots:
        root_path = Path(root)
        if not root_path.is_absolute():
            root_path = (base / root_path).resolve()
        allowed_roots.append(str(root_path))
    return PolicyConfig(
        allowed_roots=allowed_roots,
        blocked_path_patterns=data.get("blocked_path_patterns", []),
        blocked_content_patterns=data.get("blocked_content_patterns", []),
        allow_network=bool(data.get("allow_network", False)),
        allowed_domains=data.get("allowed_domains", []),
        max_bytes_read=int(data.get("max_bytes_read", 262144)),
        max_bytes_write=int(data.get("max_bytes_write", 262144)),
        max_http_bytes=int(data.get("max_http_bytes", 262144)),
        allow_shell=bool(data.get("allow_shell", False)),
        redact_patterns=data.get("redact_patterns", []),
        scan_block_severity=str(data.get("scan_block_severity", "high")).lower(),
        audit_max_bytes=int(data.get("audit_max_bytes", 5_000_000)),
        audit_max_files=int(data.get("audit_max_files", 5)),
        jwt_secret=data.get("jwt_secret") or os.getenv("OBLIVIAN_JWT_SECRET") or None,
        jwt_issuer=data.get("jwt_issuer") or os.getenv("OBLIVIAN_JWT_ISSUER") or None,
        jwt_audience=data.get("jwt_audience") or os.getenv("OBLIVIAN_JWT_AUDIENCE") or None,
        agent_policies=data.get("agent_policies", {}) or {},
        alert_webhook_url=data.get("alert_webhook_url") or os.getenv("OBLIVIAN_ALERT_WEBHOOK_URL") or None,
        alert_webhook_timeout_seconds=int(
            data.get("alert_webhook_timeout_seconds", 5)
        ),
        alert_severity=str(data.get("alert_severity", "denied")).lower(),
        api_key=data.get("api_key") or os.getenv("OBLIVIAN_API_KEY") or None,
        rate_limit_requests=int(data.get("rate_limit_requests", 0)),
        rate_limit_window_seconds=int(data.get("rate_limit_window_seconds", 60)),
    )


def apply_agent_policy(base: PolicyConfig, agent_id: Optional[str]) -> PolicyConfig:
    if not agent_id:
        return base
    overrides = (base.agent_policies or {}).get(agent_id)
    if not overrides:
        return base
    return replace(
        base,
        allowed_roots=overrides.get("allowed_roots", base.allowed_roots),
        blocked_path_patterns=overrides.get("blocked_path_patterns", base.blocked_path_patterns),
        blocked_content_patterns=overrides.get("blocked_content_patterns", base.blocked_content_patterns),
        allow_network=bool(overrides.get("allow_network", base.allow_network)),
        allowed_domains=overrides.get("allowed_domains", base.allowed_domains),
        max_bytes_read=int(overrides.get("max_bytes_read", base.max_bytes_read)),
        max_bytes_write=int(overrides.get("max_bytes_write", base.max_bytes_write)),
        max_http_bytes=int(overrides.get("max_http_bytes", base.max_http_bytes)),
        allow_shell=bool(overrides.get("allow_shell", base.allow_shell)),
        redact_patterns=overrides.get("redact_patterns", base.redact_patterns),
        scan_block_severity=str(overrides.get("scan_block_severity", base.scan_block_severity)).lower(),
        audit_max_bytes=int(overrides.get("audit_max_bytes", base.audit_max_bytes)),
        audit_max_files=int(overrides.get("audit_max_files", base.audit_max_files)),
        alert_webhook_url=overrides.get("alert_webhook_url", base.alert_webhook_url),
        alert_webhook_timeout_seconds=int(
            overrides.get("alert_webhook_timeout_seconds", base.alert_webhook_timeout_seconds)
        ),
        alert_severity=str(overrides.get("alert_severity", base.alert_severity)).lower(),
    )
