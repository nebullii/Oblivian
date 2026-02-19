# Oblivian Security Layer — Implementation Tracker

## Implemented

### API Gateway (`oblivian/server.py`)
- [x] FastAPI HTTP server with `/v1/tool/execute`, `/v1/scan`, `/v1/health` endpoints
- [x] Request schema validation via Pydantic models
- [x] Policy-based allow/deny with 403 responses
- [x] `dry_run` mode for non-destructive policy checks
- [x] Standardized JSON response envelope (`status`, `result`, `reason`)
- [x] `request_context` passthrough for metadata

### Policy Engine (`oblivian/policy.py`, `oblivian/config.py`, `config/policy.json`)
- [x] JSON-based policy config with `OBLIVIAN_POLICY_PATH` env override
- [x] `check_read_path()` — allowed roots + blocked path patterns
- [x] `check_write_path()` — write access + content scanning
- [x] `check_http()` — HTTPS-only, domain allowlist, private IP blocking
- [x] `check_shell()` — shell access gating (disabled by default)
- [x] Symlink resolution and path normalization
- [x] Byte limits for read/write/HTTP responses

### Content Filter (`oblivian/scanner.py`, `oblivian/redaction.py`)
- [x] Prompt injection scanner with HIGH/MEDIUM severity tiers
  - [x] `javascript:` and `file://` links
  - [x] AWS metadata IP (169.254.169.254)
  - [x] `curl | bash` / `wget | bash` pipe patterns
  - [x] PowerShell `-enc` encoding
  - [x] "ignore previous instructions" variants
  - [x] Exfiltration keywords (`exfiltrate`, `secrets`, `.env`)
  - [x] Base64 blobs (200+ char sequences)
- [x] Secret redaction on output (OpenAI keys, AWS keys, generic API keys)
- [x] Markdown link and code block extraction

### Auditing (`oblivian/audit.py`)
- [x] Append-only JSONL audit log
- [x] Records: timestamp, tool, args, context, dry_run flag, decision, reason
- [x] `OBLIVIAN_AUDIT_PATH` env override
- [x] Auto-creates parent directories

### CLI (`oblivian/cli.py`)
- [x] `oblivian serve` with `--host` / `--port` flags
- [x] `oblivian scan` for standalone markdown scanning

---

## Pipeline

### Auth & Transport Security
- [ ] TLS/HTTPS support for the FastAPI server
- [ ] API key authentication (header-based)
- [ ] JWT-based agent identity tokens
- [ ] Request signing (HMAC or asymmetric)
- [ ] Mutual TLS (mTLS) for agent-to-agent communication

### Rate Limiting
- [ ] Per-agent request rate limiting
- [ ] Configurable limits in `policy.json`
- [ ] 429 responses with `Retry-After` header

### Policy Engine Enhancements
- [ ] Dynamic policy reload without server restart
- [ ] Role-based policies (e.g., agent roles with different permission sets)
- [ ] Time-based policy rules
- [ ] Policy versioning and change history

### Content Filter Enhancements
- [ ] ML-based prompt injection detection
- [ ] Custom filter chain (pluggable transformer pipeline)
- [ ] Additional secret patterns (GCP, Azure, GitHub tokens, etc.)
- [ ] Encryption of sensitive fields before logging

### Auditing Enhancements
- [ ] Log rotation (size-based and time-based)
- [ ] Structured log search/query CLI (`oblivian audit query`)
- [ ] Centralized logging support (stdout JSON for log aggregators)
- [ ] Log integrity verification (hash chaining or signatures)

### Plugin System
- [ ] Plugin interface for custom tools
- [ ] Dynamic tool registration at startup
- [ ] Plugin versioning and dependency management

### Interoperability
- [ ] Service discovery / agent registry
- [ ] Protocol versioning (`X-Oblivian-Version` header)
- [ ] Request correlation IDs for distributed tracing
- [ ] OpenAPI spec publication

### Hardening
- [ ] Process/container sandboxing (beyond filesystem isolation)
- [ ] Encryption at rest for audit logs
- [ ] Input size limits at the HTTP layer (before deserialization)
