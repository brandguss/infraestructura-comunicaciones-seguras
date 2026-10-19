"""Registro estructurado y no sensible de decisiones de acceso."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path


class AuditLogger:
    """Escribe eventos JSON Lines fuera del repositorio."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def ensure_writable(self) -> None:
        """Comprueba la disponibilidad del destino sin registrar contenido sensible."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8"):
            pass

    def record(self, *, username: str | None, operation: object, result: str, reason: str | None) -> None:
        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "username": username,
            "operation": operation if isinstance(operation, str) else None,
            "result": result,
            "reason": reason,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(event, ensure_ascii=False) + "\n")
