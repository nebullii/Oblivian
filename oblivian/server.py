from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .audit import write_audit
from .config import load_policy
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
