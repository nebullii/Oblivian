from oblivian.config import PolicyConfig
from oblivian.policy import check_http, check_read_path, check_shell, check_write_path


def make_policy(**overrides):
    base = PolicyConfig(
        allowed_roots=["/tmp"],
        blocked_path_patterns=[r"\.env$", r"secret"],
        blocked_content_patterns=[r"eval\(", r"rm\s+-rf"],
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


# --- check_read_path ---

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


def test_read_path_no_roots_allows_any():
    policy = make_policy(allowed_roots=[], blocked_path_patterns=[])
    decision = check_read_path(policy, "/etc/hosts")
    assert decision.allowed


def test_read_path_reason_contains_path(tmp_path):
    policy = make_policy(allowed_roots=[str(tmp_path)])
    decision = check_read_path(policy, "/etc/hosts")
    assert "/etc/hosts" in decision.reason


# --- check_write_path ---

def test_write_path_denied_by_content(tmp_path):
    policy = make_policy(allowed_roots=[str(tmp_path)])
    decision = check_write_path(policy, str(tmp_path / "x.py"), "eval('x')")
    assert not decision.allowed


def test_write_path_denied_by_path(tmp_path):
    policy = make_policy(allowed_roots=[str(tmp_path)])
    decision = check_write_path(policy, str(tmp_path / ".env"), "safe content")
    assert not decision.allowed


def test_write_path_allowed(tmp_path):
    policy = make_policy(allowed_roots=[str(tmp_path)], blocked_content_patterns=[])
    decision = check_write_path(policy, str(tmp_path / "notes.txt"), "hello world")
    assert decision.allowed


# --- check_http ---

def test_http_policy_blocks_when_network_disabled():
    policy = make_policy(allow_network=False)
    decision = check_http(policy, "https://example.com")
    assert not decision.allowed


def test_http_policy_blocks_http_scheme():
    policy = make_policy(allow_network=True)
    decision = check_http(policy, "http://example.com")
    assert not decision.allowed


def test_http_policy_blocks_private_hosts():
    policy = make_policy(allow_network=True)
    decision = check_http(policy, "https://127.0.0.1/")
    assert not decision.allowed


def test_http_policy_blocks_10_range():
    policy = make_policy(allow_network=True)
    assert not check_http(policy, "https://10.0.0.1/").allowed


def test_http_policy_blocks_192_168_range():
    policy = make_policy(allow_network=True)
    assert not check_http(policy, "https://192.168.1.1/").allowed


def test_http_policy_blocks_172_16_range():
    policy = make_policy(allow_network=True)
    assert not check_http(policy, "https://172.16.0.1/").allowed


def test_http_policy_blocks_link_local():
    policy = make_policy(allow_network=True)
    assert not check_http(policy, "https://169.254.1.1/").allowed


def test_http_policy_blocks_localhost_hostname():
    policy = make_policy(allow_network=True)
    assert not check_http(policy, "https://localhost/").allowed


def test_http_policy_blocks_dot_local():
    policy = make_policy(allow_network=True)
    assert not check_http(policy, "https://myservice.local/").allowed


def test_http_policy_allowlist():
    policy = make_policy(allow_network=True, allowed_domains=["example.com"])
    ok = check_http(policy, "https://example.com/path")
    bad = check_http(policy, "https://example.org/")
    assert ok.allowed
    assert not bad.allowed


def test_http_empty_allowlist_permits_any_public():
    policy = make_policy(allow_network=True, allowed_domains=[])
    decision = check_http(policy, "https://example.com/")
    assert decision.allowed


def test_http_missing_hostname():
    policy = make_policy(allow_network=True)
    decision = check_http(policy, "https:///path")
    assert not decision.allowed


# --- check_shell ---

def test_check_shell_disabled():
    policy = make_policy(allow_shell=False)
    decision = check_shell(policy, "ls -la")
    assert not decision.allowed


def test_check_shell_enabled_allowed():
    policy = make_policy(allow_shell=True, blocked_content_patterns=[])
    decision = check_shell(policy, "ls -la")
    assert decision.allowed


def test_check_shell_enabled_blocked_pattern():
    policy = make_policy(allow_shell=True, blocked_content_patterns=[r"rm\s+-rf"])
    decision = check_shell(policy, "rm -rf /")
    assert not decision.allowed
