from pathlib import Path

import pytest

from oblivian.config import PolicyConfig
from oblivian.tools import ToolError, check_tool, execute_tool


def make_policy(root: Path) -> PolicyConfig:
    return PolicyConfig(
        allowed_roots=[str(root)],
        blocked_path_patterns=[],
        blocked_content_patterns=[],
        allow_network=False,
        allowed_domains=[],
        max_bytes_read=1024,
        max_bytes_write=1024,
        max_http_bytes=1024,
        allow_shell=False,
        redact_patterns=[r"sk-[A-Za-z0-9]{10,}"],
    )


def test_write_and_read_redacted(tmp_path: Path):
    policy = make_policy(tmp_path)
    file_path = tmp_path / "note.txt"
    secret = "sk-ABCDEF1234567890"

    result = execute_tool(
        policy,
        "write_file",
        {"path": str(file_path), "content": f"token={secret}"},
    )
    assert result["bytes_written"] > 0

    read = execute_tool(policy, "read_file", {"path": str(file_path)})
    assert "[REDACTED]" in read["content"]
    assert secret not in read["content"]


def test_read_outside_root_denied(tmp_path: Path):
    policy = make_policy(tmp_path)
    with pytest.raises(ToolError):
        execute_tool(policy, "read_file", {"path": "/etc/hosts"})


def test_write_too_large_denied(tmp_path: Path):
    policy = make_policy(tmp_path)
    big = "x" * (policy.max_bytes_write + 1)
    with pytest.raises(ToolError):
        execute_tool(policy, "write_file", {"path": str(tmp_path / "big.txt"), "content": big})


def test_unknown_tool_raises(tmp_path: Path):
    policy = make_policy(tmp_path)
    with pytest.raises(ToolError, match="Unknown tool blocked"):
        execute_tool(policy, "launch_missiles", {})


def test_shell_not_implemented(tmp_path: Path):
    policy = make_policy(tmp_path)
    # shell passes policy check (allow_shell=False → ToolError from check_tool)
    # override to allow shell so we reach the "not implemented" branch
    permissive = PolicyConfig(
        allowed_roots=[str(tmp_path)],
        blocked_path_patterns=[],
        blocked_content_patterns=[],
        allow_network=False,
        allowed_domains=[],
        max_bytes_read=1024,
        max_bytes_write=1024,
        max_http_bytes=1024,
        allow_shell=True,
        redact_patterns=[],
    )
    with pytest.raises(ToolError, match="not implemented"):
        execute_tool(permissive, "shell", {"cmd": "ls"})


def test_check_tool_http_network_disabled(tmp_path: Path):
    policy = make_policy(tmp_path)
    with pytest.raises(ToolError, match="Network access disabled"):
        check_tool(policy, "http_fetch", {"url": "https://example.com"})
