from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict


DEFAULT_AUDIT_PATH = "oblivian_audit.log"


def write_audit(event: Dict[str, Any]) -> None:
    path = Path(os.getenv("OBLIVIAN_AUDIT_PATH", DEFAULT_AUDIT_PATH))
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.utcnow().isoformat() + "Z",
        **event,
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=True) + "\n")
