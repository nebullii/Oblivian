from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple


LINK_RE = re.compile(r"\[[^\]]+\]\(([^\)]+)\)")
CODE_BLOCK_RE = re.compile(r"```(\w+)?\n([\s\S]*?)```", re.MULTILINE)
HTML_TAG_RE = re.compile(r"<[^>]+>")

HIGH_PATTERNS = [
    ("javascript-link", re.compile(r"javascript:", re.IGNORECASE)),
    ("file-link", re.compile(r"file://", re.IGNORECASE)),
    ("metadata-ip", re.compile(r"169\.254\.169\.254")),
    ("curl-pipe", re.compile(r"curl\s+.*\|\s*(bash|sh)", re.IGNORECASE)),
    ("wget-pipe", re.compile(r"wget\s+.*\|\s*(bash|sh)", re.IGNORECASE)),
    ("powershell-enc", re.compile(r"powershell\s+-enc", re.IGNORECASE)),
]

MEDIUM_PATTERNS = [
    ("ignore-instructions", re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE)),
    ("exfiltrate", re.compile(r"exfiltrate|secrets|\.env", re.IGNORECASE)),
    ("base64-blob", re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")),
]


@dataclass
class Finding:
    severity: str
    kind: str
    match: str


@dataclass
class ScanResult:
    findings: List[Finding]
    links: List[str]
    code_blocks: List[Dict[str, str]]
    html_blocks: List[str]


def scan_markdown(text: str) -> ScanResult:
    findings: List[Finding] = []

    for kind, pattern in HIGH_PATTERNS:
        for m in pattern.finditer(text):
            findings.append(Finding("high", kind, m.group(0)[:200]))

    for kind, pattern in MEDIUM_PATTERNS:
        for m in pattern.finditer(text):
            findings.append(Finding("medium", kind, m.group(0)[:200]))

    links = LINK_RE.findall(text)
    code_blocks = []
    for m in CODE_BLOCK_RE.finditer(text):
        lang = (m.group(1) or "").strip()
        body = m.group(2)[:5000]
        code_blocks.append({"lang": lang, "body": body})

    html_blocks = [m.group(0) for m in HTML_TAG_RE.finditer(text)]

    return ScanResult(findings=findings, links=links, code_blocks=code_blocks, html_blocks=html_blocks)


def scan_markdown_to_dict(text: str) -> Dict:
    result = scan_markdown(text)
    return {
        "findings": [asdict(f) for f in result.findings],
        "links": result.links,
        "code_blocks": result.code_blocks,
        "html_blocks": result.html_blocks,
    }
