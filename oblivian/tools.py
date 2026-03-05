from __future__ import annotations

from pathlib import Path
import socket
from typing import Any, Dict
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .config import PolicyConfig
from .policy import check_http, check_read_path, check_shell, check_write_path, is_private_ip
from .redaction import redact


class ToolError(Exception):
    pass


def check_tool(policy: PolicyConfig, tool_name: str, args: Dict[str, Any]) -> None:
    if tool_name == "read_file":
        path = str(args.get("path", ""))
        decision = check_read_path(policy, path)
        if not decision.allowed:
            raise ToolError(decision.reason)
        return

    if tool_name == "write_file":
        path = str(args.get("path", ""))
        content = str(args.get("content", ""))
        decision = check_write_path(policy, path, content)
        if not decision.allowed:
            raise ToolError(decision.reason)
        return

    if tool_name == "http_fetch":
        url = str(args.get("url", ""))
        decision = check_http(policy, url)
        if not decision.allowed:
            raise ToolError(decision.reason)
        return

    if tool_name == "shell":
        cmd = str(args.get("cmd", ""))
        decision = check_shell(policy, cmd)
        if not decision.allowed:
            raise ToolError(decision.reason)
        return

    raise ToolError(f"Unknown tool blocked: {tool_name}")


def _read_limited(path: str, max_bytes: int) -> str:
    with open(path, "rb") as f:
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ToolError(f"Read exceeds max_bytes_read={max_bytes}")
    return data.decode("utf-8", errors="replace")


def _write_limited(path: str, content: str, max_bytes: int) -> int:
    data = content.encode("utf-8")
    if len(data) > max_bytes:
        raise ToolError(f"Write exceeds max_bytes_write={max_bytes}")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return len(data)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ToolError("Redirects are not allowed")


def _ensure_public_host(host: str) -> None:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ToolError(f"DNS resolution failed for host: {host}") from e
    for _, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if is_private_ip(ip):
            raise ToolError(f"Blocked private/internal host: {host}")


def _http_fetch(url: str, max_bytes: int) -> Dict[str, Any]:
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ToolError("URL missing hostname")
    _ensure_public_host(parsed.hostname)
    req = Request(url, headers={"User-Agent": "Oblivian/0.1"})
    opener = build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=15) as resp:
            data = resp.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ToolError(f"Response exceeds max_http_bytes={max_bytes}")
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": data.decode("utf-8", errors="replace"),
            }
    except HTTPError as e:
        if 300 <= e.code < 400:
            raise ToolError("Redirects are not allowed") from e
        raise ToolError(f"HTTP error: {e.code}") from e
    except URLError as e:
        raise ToolError(f"Network error: {e.reason}") from e


def execute_tool(policy: PolicyConfig, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    if tool_name == "read_file":
        path = str(args.get("path", ""))
        check_tool(policy, tool_name, args)
        content = _read_limited(path, policy.max_bytes_read)
        return {"path": path, "content": redact(content, policy.redact_patterns)}

    if tool_name == "write_file":
        path = str(args.get("path", ""))
        content = str(args.get("content", ""))
        check_tool(policy, tool_name, args)
        written = _write_limited(path, content, policy.max_bytes_write)
        return {"path": path, "bytes_written": written}

    if tool_name == "http_fetch":
        url = str(args.get("url", ""))
        check_tool(policy, tool_name, args)
        result = _http_fetch(url, policy.max_http_bytes)
        if isinstance(result.get("body"), str):
            result["body"] = redact(result["body"], policy.redact_patterns)
        return result

    if tool_name == "shell":
        cmd = str(args.get("cmd", ""))
        check_tool(policy, tool_name, args)
        raise ToolError("Shell execution is not implemented in Oblivian")

    raise ToolError(f"Unknown tool blocked: {tool_name}")
