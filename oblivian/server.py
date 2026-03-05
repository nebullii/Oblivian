from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
import jwt
from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import JSONResponse

from .alert import send_alert
from .audit import write_audit
from .config import apply_agent_policy, load_policy
from .ratelimiter import RateLimiter
from .scanner import scan_markdown_to_dict
from .tools import ToolError, check_tool, execute_tool


class ToolRequest(BaseModel):
    tool_name: str = Field(..., min_length=1)
    args: Dict[str, Any] = Field(default_factory=dict)
    request_context: Dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False


class ScanRequest(BaseModel):
    text: str


def create_app() -> FastAPI:
    policy = load_policy()
    app = FastAPI(title="Oblivian", version="0.1.0")

    limiter: Optional[RateLimiter] = None
    if policy.rate_limit_requests > 0:
        limiter = RateLimiter(policy.rate_limit_requests, policy.rate_limit_window_seconds)

    def _decode_jwt(token: str) -> Dict[str, Any]:
        options = {"require": ["sub"]}
        kwargs: Dict[str, Any] = {"algorithms": ["HS256"], "options": options}
        if policy.jwt_issuer:
            kwargs["issuer"] = policy.jwt_issuer
        if policy.jwt_audience:
            kwargs["audience"] = policy.jwt_audience
        return jwt.decode(token, policy.jwt_secret, **kwargs)

    def _get_bearer_token(request: Request) -> Optional[str]:
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth.split(" ", 1)[1].strip()
        return request.headers.get("X-Agent-Token")

    @app.middleware("http")
    async def enforce_auth(request: Request, call_next):
        if request.url.path == "/v1/health":
            return await call_next(request)
        if policy.jwt_secret is None and policy.api_key is None:
            return await call_next(request)

        token = _get_bearer_token(request)
        if policy.jwt_secret and token:
            try:
                claims = _decode_jwt(token)
                request.state.agent_id = claims.get("agent_id") or claims.get("sub")
                request.state.auth_type = "jwt"
                return await call_next(request)
            except jwt.PyJWTError:
                return JSONResponse({"detail": "Unauthorized"}, status_code=401)

        if policy.api_key is not None and request.headers.get("X-API-Key") == policy.api_key:
            request.state.agent_id = None
            request.state.auth_type = "api_key"
            return await call_next(request)

        return JSONResponse({"detail": "Unauthorized"}, status_code=401)

    @app.middleware("http")
    async def enforce_rate_limit(request: Request, call_next):
        if limiter is None or request.url.path == "/v1/health":
            return await call_next(request)
        key = (
            request.headers.get("X-API-Key")
            or request.headers.get("Authorization")
            or request.headers.get("X-Agent-Token")
            or (request.client.host if request.client else "unknown")
        )
        allowed, retry_after = limiter.is_allowed(key)
        if not allowed:
            return JSONResponse(
                {"detail": "Rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)

    @app.get("/v1/health")
    def health() -> Dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/tool/execute")
    def tool_execute(req: ToolRequest, request: Request) -> Dict[str, Any]:
        api_key_header = request.headers.get("X-API-Key") or ""
        api_key_hash = hashlib.sha256(api_key_header.encode("utf-8")).hexdigest() if api_key_header else None
        agent_id = getattr(request.state, "agent_id", None)
        effective_policy = apply_agent_policy(policy, agent_id)

        scan_input = json.dumps(
            {"tool_name": req.tool_name, "args": req.args, "context": req.request_context},
            ensure_ascii=True,
        )
        scan = scan_markdown_to_dict(scan_input)
        block_severity = effective_policy.scan_block_severity or "high"
        severity_order = {"low": 1, "medium": 2, "high": 3}
        threshold = severity_order.get(block_severity, 3)
        has_blocked = any(
            severity_order.get(f.get("severity", ""), 0) >= threshold
            for f in scan.get("findings", [])
        )

        client_ip = request.client.host if request.client else None

        event = {
            "tool_name": req.tool_name,
            "args": req.args,
            "context": req.request_context,
            "dry_run": req.dry_run,
            "scan": scan,
            "client_ip": client_ip,
            "api_key_hash": api_key_hash,
            "agent_id": agent_id,
        }

        if has_blocked:
            decision = {
                "status": "denied",
                "reason": f"Scan blocked: {block_severity} severity findings",
                "scan": scan,
            }
            write_audit({**event, **decision}, effective_policy.audit_max_bytes, effective_policy.audit_max_files)
            send_alert(effective_policy, {**event, **decision})
            if req.dry_run:
                return decision
            raise HTTPException(status_code=403, detail=decision["reason"])

        if req.dry_run:
            try:
                check_tool(effective_policy, req.tool_name, req.args)
                decision = {"status": "allowed", "scan": scan}
            except ToolError as e:
                decision = {"status": "denied", "reason": str(e), "scan": scan}
            write_audit({**event, **decision}, effective_policy.audit_max_bytes, effective_policy.audit_max_files)
            send_alert(effective_policy, {**event, **decision})
            return decision

        try:
            result = execute_tool(effective_policy, req.tool_name, req.args)
            write_audit({**event, "status": "allowed"}, effective_policy.audit_max_bytes, effective_policy.audit_max_files)
            return {"status": "ok", "result": result, "scan": scan}
        except ToolError as e:
            denial = {**event, "status": "denied", "reason": str(e)}
            write_audit(denial, effective_policy.audit_max_bytes, effective_policy.audit_max_files)
            send_alert(effective_policy, denial)
            raise HTTPException(status_code=403, detail=str(e))

    @app.post("/v1/scan")
    def scan(req: ScanRequest) -> Dict[str, Any]:
        return scan_markdown_to_dict(req.text)

    return app
