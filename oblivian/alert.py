from __future__ import annotations

import json
from typing import Any, Dict, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from .config import PolicyConfig


def _should_alert(policy: PolicyConfig, event: Dict[str, Any]) -> bool:
    severity = policy.alert_severity or "denied"
    if severity == "off":
        return False
    if event.get("status") == "denied":
        return True
    findings = (event.get("scan") or {}).get("findings", [])
    if not findings:
        return False
    severity_order = {"low": 1, "medium": 2, "high": 3}
    threshold = severity_order.get(severity, 3)
    return any(severity_order.get(f.get("severity", ""), 0) >= threshold for f in findings)


def send_alert(policy: PolicyConfig, event: Dict[str, Any]) -> Optional[str]:
    if not policy.alert_webhook_url:
        return None
    if not _should_alert(policy, event):
        return None
    payload = json.dumps(event, ensure_ascii=True).encode("utf-8")
    req = Request(
        policy.alert_webhook_url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Oblivian/0.1"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=policy.alert_webhook_timeout_seconds) as resp:
            return f"{resp.status}"
    except URLError:
        return None
