from __future__ import annotations

import re
from typing import Iterable


def redact(text: str, patterns: Iterable[str]) -> str:
    redacted = text
    for pat in patterns:
        redacted = re.sub(pat, "[REDACTED]", redacted, flags=re.IGNORECASE)
    return redacted
