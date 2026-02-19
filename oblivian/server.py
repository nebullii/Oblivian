from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import JSONResponse

from .audit import write_audit
from .config import load_policy
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

    # Rate limiting registered first → innermost; auth registered second → outermost.
    # FastAPI/Starlette middleware is LIFO, so auth executes first on incoming requests.
    @app.middleware("http")
    async def enforce_rate_limit(request: Request, call_next):
        if limiter is None or request.url.path == "/v1/health":
            return await call_next(request)
        key = request.headers.get("X-API-Key") or (request.client.host if request.client else "unknown")
        allowed, retry_after = limiter.is_allowed(key)
        if not allowed:
            return JSONResponse(
                {"detail": "Rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)

    @app.middleware("http")
    async def enforce_api_key(request: Request, call_next):
        if policy.api_key is None or request.url.path == "/v1/health":
            return await call_next(request)
        if request.headers.get("X-API-Key") != policy.api_key:
            return JSONResponse({"detail": "Unauthorized"}, status_code=401)
        return await call_next(request)

    @app.get("/v1/health")
    def health() -> Dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/tool/execute")
    def tool_execute(req: ToolRequest) -> Dict[str, Any]:
        event = {
            "tool_name": req.tool_name,
            "args": req.args,
            "context": req.request_context,
            "dry_run": req.dry_run,
        }

        if req.dry_run:
            try:
                check_tool(policy, req.tool_name, req.args)
                decision = {"status": "allowed"}
            except ToolError as e:
                decision = {"status": "denied", "reason": str(e)}
            write_audit({**event, **decision})
            return decision

        try:
            result = execute_tool(policy, req.tool_name, req.args)
            write_audit({**event, "status": "allowed"})
            return {"status": "ok", "result": result}
        except ToolError as e:
            write_audit({**event, "status": "denied", "reason": str(e)})
            raise HTTPException(status_code=403, detail=str(e))

    @app.post("/v1/scan")
    def scan(req: ScanRequest) -> Dict[str, Any]:
        return scan_markdown_to_dict(req.text)

    return app
