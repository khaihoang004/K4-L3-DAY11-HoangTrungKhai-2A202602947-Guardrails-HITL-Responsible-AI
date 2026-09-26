"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from uuid import uuid4


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input and a monotonic start time for latency measurement."""
        key = request_id or user_id
        self._open[key] = {"user_id": user_id, "input": text,
                           "started_at": utc_now_iso(), "start": monotonic()}

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Append the completed request with its decision and latency."""
        key = request_id or user_id
        opened = self._open.pop(key, None)
        self.logs.append({
            "request_id": request_id or str(uuid4()), "user_id": user_id,
            "input": opened["input"] if opened else None,
            "started_at": opened["started_at"] if opened else None,
            "finished_at": utc_now_iso(),
            "latency_ms": round((monotonic() - opened["start"]) * 1000, 2) if opened else None,
            "output": text, "blocked": blocked, "layer": layer,
        })

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
