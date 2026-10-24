"""Tool-call trace: a JSONL record of every reasoning step and tool execution.

The trace lets a reviewer verify that the LLM, not a fixed script, directed the
investigation. Everything written here is redacted first.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, TextIO

from auditor.redaction import redact


class TraceLogger:
    def __init__(self, path: str | Path | None = None, console: TextIO | None = sys.stderr, verbose: bool = False):
        self.path = Path(path) if path else None
        self.console = console
        self.verbose = verbose
        self._fh = None
        self._t0 = time.monotonic()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self.path, "w", encoding="utf-8")

    def event(self, kind: str, **data: Any) -> None:
        record = {"t": round(time.monotonic() - self._t0, 2), "event": kind, **data}
        if self._fh:
            self._fh.write(redact(json.dumps(record, ensure_ascii=False, default=str)) + "\n")
            self._fh.flush()

    def say(self, message: str) -> None:
        if self.console:
            print(redact(message), file=self.console, flush=True)

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> TraceLogger:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
