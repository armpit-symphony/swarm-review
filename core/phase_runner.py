"""Phase execution helpers with structured event logging."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class PhaseEvent:
    phase: str
    status: str
    started_at: str
    ended_at: str
    duration_ms: int
    meta: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_ms": self.duration_ms,
            "meta": self.meta,
        }


class PhaseRunner:
    """Runs named phases and records start/stop/duration events."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def run_phase(self, phase: str, fn: Callable[[], Any], meta: dict[str, Any] | None = None) -> Any:
        start_ts = _utc_now()
        start = time.perf_counter()
        status = "ok"
        phase_meta = dict(meta or {})
        result: Any = None
        err: Exception | None = None
        try:
            result = fn()
            return result
        except Exception as exc:
            status = "error"
            err = exc
            phase_meta["error"] = str(exc)
            raise
        finally:
            end = time.perf_counter()
            end_ts = _utc_now()
            event = PhaseEvent(
                phase=phase,
                status=status,
                started_at=start_ts,
                ended_at=end_ts,
                duration_ms=int((end - start) * 1000),
                meta=phase_meta,
            )
            self.events.append(event.as_dict())
            if err is not None:
                # Keep event recorded while preserving original exception flow.
                pass

    def write_jsonl(self, path: str) -> str:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            for event in self.events:
                f.write(json.dumps(event) + "\n")
        return str(p)
