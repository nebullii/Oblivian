from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict


DEFAULT_AUDIT_PATH = "oblivian_audit.log"
DEFAULT_AUDIT_MAX_BYTES = 5_000_000
DEFAULT_AUDIT_MAX_FILES = 5


def _rotate_if_needed(path: Path, max_bytes: int, max_files: int) -> None:
    if max_files <= 1:
        return
    if path.exists() and path.stat().st_size >= max_bytes:
        # Rotate: audit.log -> audit.log.1, audit.log.1 -> audit.log.2, ...
        for idx in range(max_files - 1, 0, -1):
            src = path.with_name(f"{path.name}.{idx}")
            dst = path.with_name(f"{path.name}.{idx + 1}")
            if src.exists():
                src.replace(dst)
        path.replace(path.with_name(f"{path.name}.1"))


def write_audit(event: Dict[str, Any], max_bytes: int | None = None, max_files: int | None = None) -> None:
    path = Path(os.getenv("OBLIVIAN_AUDIT_PATH", DEFAULT_AUDIT_PATH))
    max_bytes = max_bytes if max_bytes is not None else int(
        os.getenv("OBLIVIAN_AUDIT_MAX_BYTES", DEFAULT_AUDIT_MAX_BYTES)
    )
    max_files = max_files if max_files is not None else int(
        os.getenv("OBLIVIAN_AUDIT_MAX_FILES", DEFAULT_AUDIT_MAX_FILES)
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    _rotate_if_needed(path, max_bytes, max_files)
    record = {
        "ts": datetime.utcnow().isoformat() + "Z",
        **event,
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=True) + "\n")
