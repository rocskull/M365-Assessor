from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

_SENSITIVE_KEYS = re.compile(
    r"(access[_-]?token|refresh[_-]?token|password|client[_-]?secret|private[_-]?key|certificate)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]+")


def redact(value: Any, key: str | None = None) -> Any:
    if key is not None and _SENSITIVE_KEYS.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            item_key: redact(item_value, str(item_key)) for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _BEARER.sub("Bearer [REDACTED]", value)
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(record.getMessage()),
        }
        context = getattr(record, "context", None)
        if isinstance(context, dict):
            payload["context"] = redact(context)
        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, default=str, ensure_ascii=True)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())
