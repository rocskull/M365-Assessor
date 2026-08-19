from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def validate_report_filename(filename: str, suffix: str) -> str:
    if Path(filename).name != filename or not filename.casefold().endswith(suffix.casefold()):
        raise ValueError(f"Report filename must be a simple {suffix} filename")
    return filename


@contextmanager
def atomic_report_path(destination: Path) -> Iterator[Path]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=f".{destination.stem}-", suffix=".tmp", dir=destination.parent
    )
    os.close(descriptor)
    temporary = Path(name)
    try:
        yield temporary
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
