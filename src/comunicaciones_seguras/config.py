"""Lectura y validación de la configuración de red desde el entorno."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TCPConfig:
    """Parámetros de conexión TCP compartidos por cliente y servidor."""

    host: str
    port: int


@dataclass(frozen=True)
class TLSClientConfig:
    """Material de confianza y nombre esperado por el cliente TLS."""

    ca_file: Path
    server_name: str


@dataclass(frozen=True)
class TLSServerConfig:
    """Certificado público y clave privada que usa el servidor TLS."""

    cert_file: Path
    key_file: Path


@dataclass(frozen=True)
class AuthConfig:
    """Rutas externas para usuarios y eventos de auditoría."""

    users_file: Path
    audit_log_file: Path


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


def load_communication_mode() -> str:
    """Obtiene el modo de transporte solicitado: tcp o tls."""
    mode = os.getenv("COMMUNICATION_MODE", "tcp").strip().lower()
    if mode not in {"tcp", "tls"}:
        raise ValueError("COMMUNICATION_MODE debe ser 'tcp' o 'tls'.")
    return mode


def _required_path(variable: str) -> Path:
    value = os.getenv(variable, "").strip()
    if not value:
        raise ValueError(f"Debe definir la variable {variable} para usar TLS.")
    return Path(value)


def load_tls_client_config() -> TLSClientConfig:
    """Carga la CA explícitamente confiada y el nombre TLS esperado."""
    server_name = os.getenv("TLS_SERVER_NAME", os.getenv("TCP_HOST", "127.0.0.1")).strip()
    if not server_name:
        raise ValueError("TLS_SERVER_NAME no puede estar vacío.")
    return TLSClientConfig(ca_file=_required_path("TLS_CA_FILE"), server_name=server_name)


def load_tls_server_config() -> TLSServerConfig:
    """Carga el certificado y la clave privados, que deben estar fuera del repositorio."""
    return TLSServerConfig(
        cert_file=_required_path("TLS_CERT_FILE"),
        key_file=_required_path("TLS_KEY_FILE"),
    )


def load_auth_config() -> AuthConfig:
    """Carga las rutas que habilitan las operaciones protegidas del servidor."""
    return AuthConfig(
        users_file=_required_path("AUTH_USERS_FILE"),
        audit_log_file=_required_path("AUDIT_LOG_FILE"),
    )
