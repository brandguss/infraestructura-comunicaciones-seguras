"""Lectura y validación de la configuración de red desde el entorno."""

from __future__ import annotations

import base64
import binascii
import json
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
    """Ruta externa del almacén de usuarios."""

    users_file: Path


@dataclass(frozen=True)
class AuditConfig:
    """Ruta externa para eventos estructurados de auditoría."""

    audit_log_file: Path


@dataclass(frozen=True)
class TransportSecurityConfig:
    """Controles del servidor para transporte inseguro y tiempos de espera."""

    allow_insecure_tcp_auth: bool
    connection_timeout_seconds: int
    tls_handshake_timeout_seconds: int


@dataclass(frozen=True)
class SSHIntegrationConfig:
    """Configuración externa para una prueba de integración OpenSSH."""

    executable: str
    host: str
    user: str
    private_key_file: Path
    port: int
    timeout_seconds: int
    known_hosts_file: Path | None


@dataclass(frozen=True)
class IPSecSimulationSettings:
    """Configuración externa de la simulación educativa tipo IPSec."""

    key: bytes
    spi: str
    mode: str
    replay_window: int
    max_message_bytes: int
    sequence_start: int


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


def _load_boolean(variable: str, default: bool = False) -> bool:
    value = os.getenv(variable, "1" if default else "0").strip().lower()
    if value in {"1", "true", "yes"}:
        return True
    if value in {"", "0", "false", "no"}:
        return False
    raise ValueError(f"{variable} debe ser 0 o 1.")


def _load_timeout(variable: str, default: int) -> int:
    try:
        timeout = int(os.getenv(variable, str(default)))
    except ValueError as error:
        raise ValueError(f"{variable} debe ser un número entero.") from error
    if not 1 <= timeout <= 60:
        raise ValueError(f"{variable} debe estar entre 1 y 60 segundos.")
    return timeout


def load_transport_security_config() -> TransportSecurityConfig:
    """Carga controles seguros; la autenticación sobre TCP queda desactivada por defecto."""
    return TransportSecurityConfig(
        allow_insecure_tcp_auth=_load_boolean("ALLOW_INSECURE_TCP_AUTH"),
        connection_timeout_seconds=_load_timeout("CONNECTION_TIMEOUT_SECONDS", 10),
        tls_handshake_timeout_seconds=_load_timeout("TLS_HANDSHAKE_TIMEOUT_SECONDS", 10),
    )


def _required_path(variable: str) -> Path:
    value = os.getenv(variable, "").strip()
    if not value:
        raise ValueError(f"Debe definir la variable {variable}.")
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
    return AuthConfig(users_file=_required_path("AUTH_USERS_FILE"))


def load_audit_config() -> AuditConfig:
    """Carga la ruta de auditoría independientemente del almacén de usuarios."""
    return AuditConfig(audit_log_file=_required_path("AUDIT_LOG_FILE"))


def load_ssh_integration_config() -> SSHIntegrationConfig:
    """Lee la configuración de prueba sin inspeccionar el contenido de ninguna clave."""
    host = os.getenv("SSH_TEST_HOST", "").strip()
    user = os.getenv("SSH_TEST_USER", "").strip()
    key_file = os.getenv("SSH_TEST_PRIVATE_KEY_FILE", "").strip()
    executable = os.getenv("SSH_EXECUTABLE", "ssh").strip()
    if not host or host.startswith("-") or "@" in host or any(character.isspace() for character in host):
        raise ValueError("SSH_TEST_HOST es obligatorio y debe ser un host sin espacios ni opciones.")
    if not user or user.startswith("-") or "@" in user or any(character.isspace() for character in user):
        raise ValueError("SSH_TEST_USER es obligatorio y debe ser un usuario sin espacios ni opciones.")
    if not key_file:
        raise ValueError("SSH_TEST_PRIVATE_KEY_FILE es obligatorio.")
    if not executable:
        raise ValueError("SSH_EXECUTABLE no puede estar vacío.")
    try:
        port = int(os.getenv("SSH_TEST_PORT", "22"))
        timeout_seconds = int(os.getenv("SSH_TEST_TIMEOUT", "15"))
    except ValueError as error:
        raise ValueError("SSH_TEST_PORT y SSH_TEST_TIMEOUT deben ser enteros.") from error
    if not 1 <= port <= 65535 or not 1 <= timeout_seconds <= 60:
        raise ValueError("SSH_TEST_PORT o SSH_TEST_TIMEOUT están fuera del rango seguro.")
    known_hosts = os.getenv("SSH_TEST_KNOWN_HOSTS_FILE", "").strip()
    return SSHIntegrationConfig(
        executable=executable,
        host=host,
        user=user,
        private_key_file=Path(key_file),
        port=port,
        timeout_seconds=timeout_seconds,
        known_hosts_file=Path(known_hosts) if known_hosts else None,
    )


def ipsec_simulation_enabled() -> bool:
    """Indica si se debe activar la capa opcional de encapsulado simulado."""
    value = os.getenv("IPSEC_SIM_ENABLED", "0").strip().lower()
    if value in {"", "0", "false", "no"}:
        return False
    if value in {"1", "true", "yes"}:
        return True
    raise ValueError("IPSEC_SIM_ENABLED debe ser 0 o 1.")


def load_ipsec_simulation_settings() -> IPSecSimulationSettings:
    """Carga clave externa y parámetros; no expone el material secreto en errores."""
    key_path = _required_path("IPSEC_SIM_KEY_FILE")
    try:
        document = json.loads(key_path.read_text(encoding="utf-8"))
        if set(document) != {"key_b64"}:
            raise ValueError("campos inesperados")
        key = base64.b64decode(document["key_b64"].encode("ascii"), validate=True)
        if len(key) != 32:
            raise ValueError("longitud de clave inválida")
    except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError, UnicodeEncodeError, binascii.Error) as error:
        raise ValueError("No se pudo cargar la clave externa de simulación.") from error
    spi = os.getenv("IPSEC_SIM_SPI", "").strip()
    mode = os.getenv("IPSEC_SIM_MODE", "transport").strip().lower()
    try:
        replay_window = int(os.getenv("IPSEC_SIM_REPLAY_WINDOW", "64"))
        max_message_bytes = int(os.getenv("IPSEC_SIM_MAX_MESSAGE_BYTES", "2048"))
        sequence_start = int(os.getenv("IPSEC_SIM_SEQUENCE_START", "1"))
    except ValueError as error:
        raise ValueError("Los parámetros numéricos de simulación deben ser enteros.") from error
    settings = IPSecSimulationSettings(key, spi, mode, replay_window, max_message_bytes, sequence_start)
    try:
        # Mantiene los errores de configuración fuera de la ruta de procesamiento de paquetes.
        from .ipsec_sim import IPSecSimulationConfig

        IPSecSimulationConfig(**settings.__dict__)
    except ValueError as error:
        raise ValueError("Los parámetros de simulación no son válidos.") from error
    return settings
