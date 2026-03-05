# Oblivian

Portable sidecar firewall + offline Markdown scanner for agent tool calls.

## What it does

- Enforces a policy for file, network, and shell tools (default-deny).
- Redacts secrets from tool outputs.
- Audits every decision to a log file.
- Scans all tool requests for common prompt-injection patterns (blocking on high severity).
- Authenticates agents via API key (`X-API-Key` header).
- Supports TLS via uvicorn (`--ssl-certfile` / `--ssl-keyfile`).

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .

# Run the sidecar
oblivian serve --host 127.0.0.1 --port 8080

# Scan Markdown
oblivian scan docs/skill.md --fail-on-high
```

## Policy config

Default policy lives at `config/policy.json`. Relative `allowed_roots` are resolved relative to the policy file directory. Override with:

```bash
export OBLIVIAN_POLICY_PATH=/path/to/policy.json
```

Key settings:

- `allowed_roots`: list of filesystem roots allowed for read/write
- `blocked_path_patterns`: regex patterns for sensitive files
- `blocked_content_patterns`: regex patterns for dangerous code
- `allow_network`: enable/disable http fetches
- `allowed_domains`: optional HTTPS allowlist
- `allow_shell`: enable/disable shell tool
- `max_bytes_read` / `max_bytes_write` / `max_http_bytes`
- `scan_block_severity`: block tool calls when scan finds `low|medium|high` severity (default: `high`)
- `audit_max_bytes` / `audit_max_files`: rotate audit logs by size
- `jwt_secret` / `jwt_issuer` / `jwt_audience`: enable JWT auth for agent identity
- `agent_policies`: per-agent policy overrides by `sub` or `agent_id`
- `alert_webhook_url`: POST audit events to a webhook on denies/high scans
- `alert_severity`: `off|low|medium|high|denied` (default: `denied`)

## Authentication

Set an API key in `policy.json` or via env var:

```bash
export OBLIVIAN_API_KEY=your-secret-key
```

Or in `policy.json`:
```json
{ "api_key": "your-secret-key" }
```

All requests (except `GET /v1/health`) must include:
```
X-API-Key: your-secret-key
```

Missing or wrong key returns `401`. If no key is configured, auth is disabled.

### JWT (Agent Identity)

If `jwt_secret` is set, Oblivian accepts JWTs via:
- `Authorization: Bearer <token>`
- `X-Agent-Token: <token>`

JWTs must include `sub` (or `agent_id`). Optional `jwt_issuer` and `jwt_audience` can be enforced.
Use a long, random `jwt_secret` (32+ bytes recommended).

## Environment

Copy `.env.example` to `.env` and set values for local development. `.env` is ignored by git.

Per-agent overrides are configured under `agent_policies` keyed by `sub`/`agent_id`.

## TLS

```bash
# Generate a self-signed cert (dev only)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Start with TLS enabled
oblivian serve --ssl-certfile cert.pem --ssl-keyfile key.pem
```

For production use a cert from your internal CA or Let's Encrypt.

## Deploy on Railway

See `DEPLOYMENT_RAILWAY.md`.

## HTTP API

`POST /v1/tool/execute`

```json
{
  "tool_name": "read_file",
  "args": {"path": "/project/README.md"},
  "request_context": {"task_id": "t1"}
}
```

`POST /v1/scan`

```json
{ "text": "# Skill\nDo not ignore previous instructions" }
```

Audit log path defaults to `./oblivian_audit.log` and can be overridden with `OBLIVIAN_AUDIT_PATH`.
