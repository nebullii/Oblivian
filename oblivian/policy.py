from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Tuple
from urllib.parse import urlparse

from .config import PolicyConfig


PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
]


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


def _match_any(patterns: Iterable[str], text: str) -> Optional[str]:
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            return pat
    return None


def _normalize_path(path: str) -> str:
    return str(Path(path).resolve())


def _is_under_root(path: str, root: str) -> bool:
    try:
        return Path(path).resolve().is_relative_to(Path(root).resolve())
    except AttributeError:
        # Python <3.9 fallback
        return str(Path(path).resolve()).startswith(str(Path(root).resolve()))


def check_read_path(policy: PolicyConfig, path: str) -> PolicyDecision:
    norm = _normalize_path(path)
    if policy.allowed_roots:
        if not any(_is_under_root(norm, root) for root in policy.allowed_roots):
            return PolicyDecision(False, f"File access outside allowed roots: {path}")
    hit = _match_any(policy.blocked_path_patterns, norm)
    if hit:
        return PolicyDecision(False, f"Blocked sensitive path pattern ({hit}) for: {path}")
    return PolicyDecision(True, "OK")


def check_write_path(policy: PolicyConfig, path: str, content: str) -> PolicyDecision:
    path_decision = check_read_path(policy, path)
    if not path_decision.allowed:
        return path_decision
    hit = _match_any(policy.blocked_content_patterns, content)
    if hit:
        return PolicyDecision(False, f"Blocked content pattern ({hit}) in write")
    return PolicyDecision(True, "OK")


def _is_private_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in PRIVATE_NETS)
    except ValueError:
        host = host.lower()
        return host in {"localhost"} or host.endswith(".local")


def check_http(policy: PolicyConfig, url: str) -> PolicyDecision:
    if not policy.allow_network:
        return PolicyDecision(False, "Network access disabled by policy")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return PolicyDecision(False, "Only https URLs are allowed")
    if not parsed.hostname:
        return PolicyDecision(False, "URL missing hostname")
    if _is_private_host(parsed.hostname):
        return PolicyDecision(False, f"Blocked private/internal host: {parsed.hostname}")
    if policy.allowed_domains:
        if parsed.hostname not in policy.allowed_domains:
            return PolicyDecision(False, f"Domain not on allowlist: {parsed.hostname}")
    return PolicyDecision(True, "OK")


def check_shell(policy: PolicyConfig, cmd: str) -> PolicyDecision:
    if not policy.allow_shell:
        return PolicyDecision(False, "Shell disabled by policy")
    hit = _match_any(policy.blocked_content_patterns, cmd)
    if hit:
        return PolicyDecision(False, f"Blocked shell pattern ({hit})")
    return PolicyDecision(True, "OK")
