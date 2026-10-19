"""Lectura y validación de la configuración de red desde el entorno."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class TCPConfig:
    """Parámetros de conexión TCP compartidos por cliente y servidor."""

    host: str
    port: int


def load_tcp_config() -> TCPConfig:
    """Obtiene TCP_HOST y TCP_PORT y comprueba que contienen valores válidos."""
    host = os.getenv("TCP_HOST", "127.0.0.1").strip()
    if not host:
        raise ValueError("TCP_HOST no puede estar vacío.")

    raw_port = os.getenv("TCP_PORT", "5000")
    try:
        port = int(raw_port)
    except ValueError as error:
        raise ValueError("TCP_PORT debe ser un número entero.") from error

    if not 1 <= port <= 65535:
        raise ValueError("TCP_PORT debe estar entre 1 y 65535.")

    return TCPConfig(host=host, port=port)
