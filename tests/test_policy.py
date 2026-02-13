from oblivian.config import PolicyConfig
from oblivian.policy import check_http, check_read_path, check_write_path


def make_policy(**overrides):
    base = PolicyConfig(
        allowed_roots=["/tmp"],
        blocked_path_patterns=[r"\.env$", r"secret"],
        blocked_content_patterns=[r"eval\\(", r"rm\\s+-rf"],
        allow_network=False,
        allowed_domains=[],
        max_bytes_read=1024,
        max_bytes_write=1024,
        max_http_bytes=1024,
        allow_shell=False,
        redact_patterns=[],
    )
    data = base.__dict__ | overrides
    return PolicyConfig(**data)


def test_read_path_allowed_under_root(tmp_path):
    policy = make_policy(allowed_roots=[str(tmp_path)])
    decision = check_read_path(policy, str(tmp_path / "file.txt"))
    assert decision.allowed


def test_read_path_denied_outside_root(tmp_path):
    policy = make_policy(allowed_roots=[str(tmp_path)])
    decision = check_read_path(policy, "/etc/hosts")
    assert not decision.allowed


def test_read_path_denied_by_pattern(tmp_path):
    policy = make_policy(allowed_roots=[str(tmp_path)])
    decision = check_read_path(policy, str(tmp_path / ".env"))
    assert not decision.allowed


def test_write_path_denied_by_content(tmp_path):
    policy = make_policy(allowed_roots=[str(tmp_path)])
    decision = check_write_path(policy, str(tmp_path / "x.py"), "eval('x')")
    assert not decision.allowed


def test_http_policy_blocks_when_network_disabled():
    policy = make_policy(allow_network=False)
    decision = check_http(policy, "https://example.com")
    assert not decision.allowed


def test_http_policy_blocks_private_hosts():
    policy = make_policy(allow_network=True)
    decision = check_http(policy, "https://127.0.0.1/")
    assert not decision.allowed


def test_http_policy_allowlist():
    policy = make_policy(allow_network=True, allowed_domains=["example.com"])
    ok = check_http(policy, "https://example.com/path")
    bad = check_http(policy, "https://example.org/")
    assert ok.allowed
    assert not bad.allowed
