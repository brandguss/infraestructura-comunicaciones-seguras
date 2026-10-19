"""Servidor TCP sencillo para la primera etapa del proyecto."""

from __future__ import annotations

import logging
import json
import socket
import ssl
from typing import Final

from .audit import AuditLogger
from .auth import AccessController, AuthenticationError, AuthorizationError, UserStoreError
from .config import (
    TCPConfig,
    TLSServerConfig,
    load_communication_mode,
    load_audit_config,
    load_auth_config,
    load_tcp_config,
    load_tls_server_config,
    load_transport_security_config,
    ipsec_simulation_enabled,
    load_ipsec_simulation_settings,
)
from .ipsec_sim import IPSecSimulationConfig, IPSecSimulationError, IPSecSimulator

BUFFER_SIZE: Final = 4096
LOGGER = logging.getLogger(__name__)


def _send_protected_response(connection: socket.socket, message: dict[str, object]) -> None:
    connection.sendall(json.dumps(message, ensure_ascii=False).encode("utf-8"))


def _handle_protected_request(
    connection: socket.socket,
    request: dict[str, object],
    controller: AccessController | None,
    audit_logger: AuditLogger | None,
    protected_error: str | None,
) -> None:
    username = request.get("username") if isinstance(request.get("username"), str) else None
    operation = request.get("operation")
    if controller is None or audit_logger is None:
        LOGGER.warning("Operación protegida rechazada por configuración: %s", protected_error)
        _send_protected_response(connection, {"result": "denied", "reason": "servicio_no_disponible"})
        return
    try:
        user, data = controller.execute(username, request.get("password"), operation)
        audit_logger.record(username=user.username, operation=operation, result="allowed", reason=None)
        _send_protected_response(connection, {"result": "ok", "operation": operation, "data": data})
    except AuthenticationError:
        audit_logger.record(username=username, operation=operation, result="denied", reason="credenciales_invalidas")
        _send_protected_response(connection, {"result": "denied", "reason": "acceso_denegado"})
    except AuthorizationError:
        audit_logger.record(username=username, operation=operation, result="denied", reason="permiso_insuficiente")
        _send_protected_response(connection, {"result": "denied", "reason": "acceso_denegado"})
    except OSError as error:
        LOGGER.error("No se pudo registrar la auditoría: %s", error)
        _send_protected_response(connection, {"result": "denied", "reason": "servicio_no_disponible"})


def _record_ipsec_rejection(audit_logger: AuditLogger | None, reason: str) -> None:
    if audit_logger is None:
        return
    try:
        audit_logger.record(username=None, operation="ipsec_sim", result="denied", reason=reason)
    except OSError as error:
        LOGGER.error("No se pudo registrar el rechazo de simulación: %s", error)


def _record_transport_rejection(audit_logger: AuditLogger | None, reason: str) -> None:
    """Registra rechazos de transporte sin conservar contenido de la solicitud."""
    if audit_logger is None:
        return
    try:
        audit_logger.record(username=None, operation="transport", result="denied", reason=reason)
    except OSError as error:
        LOGGER.error("No se pudo registrar el rechazo de transporte: %s", error)


def handle_connection(
    connection: socket.socket,
    address: tuple[str, int],
    controller: AccessController | None = None,
    audit_logger: AuditLogger | None = None,
    protected_error: str | None = None,
    ipsec_simulator: IPSecSimulator | None = None,
    ipsec_required: bool = False,
    transport_is_tls: bool = False,
    allow_insecure_tcp_auth: bool = False,
) -> None:
    """Procesa un mensaje de un cliente y devuelve una confirmación."""
    try:
        data = connection.recv(BUFFER_SIZE)
        if not data:
            LOGGER.warning("Conexión vacía desde %s:%s", *address)
            return

        message = data.decode("utf-8")
        if ipsec_required:
            if ipsec_simulator is None:
                _record_ipsec_rejection(audit_logger, "ipsec_configuration_unavailable")
                connection.sendall(b"ERROR: simulacion de encapsulado no disponible")
                return
            try:
                message = ipsec_simulator.decapsulate(message)
            except IPSecSimulationError as error:
                _record_ipsec_rejection(audit_logger, error.reason)
                connection.sendall(b"ERROR: paquete de simulacion rechazado")
                return
        LOGGER.info("Mensaje recibido de %s:%s", *address)
        try:
            request = json.loads(message)
        except json.JSONDecodeError:
            request = None
        if isinstance(request, dict) and "operation" in request:
            if not transport_is_tls and not allow_insecure_tcp_auth:
                _record_transport_rejection(audit_logger, "tcp_authentication_not_allowed")
                _send_protected_response(connection, {"result": "denied", "reason": "canal_inseguro"})
                return
            _handle_protected_request(connection, request, controller, audit_logger, protected_error)
        else:
            # Compatibilidad deliberada con el eco TCP de la etapa 1.
            connection.sendall(f"RECIBIDO: {message}".encode("utf-8"))
    except TimeoutError:
        LOGGER.warning("Tiempo de espera de conexión desde %s:%s", *address)
        _record_transport_rejection(audit_logger, "connection_timeout")
        try:
            connection.sendall(b"ERROR: tiempo de espera de conexion")
        except OSError:
            pass
    except UnicodeDecodeError:
        LOGGER.warning("Datos no UTF-8 rechazados desde %s:%s", *address)
        connection.sendall(b"ERROR: el mensaje debe usar UTF-8")
    except OSError as error:
        LOGGER.error("Error con %s:%s: %s", *address, error)
    finally:
        connection.close()
        LOGGER.info("Conexión cerrada con %s:%s", *address)


def serve(
    config: TCPConfig,
    controller: AccessController | None = None,
    audit_logger: AuditLogger | None = None,
    protected_error: str | None = None,
    ipsec_simulator: IPSecSimulator | None = None,
    ipsec_required: bool = False,
    connection_timeout_seconds: int = 10,
    allow_insecure_tcp_auth: bool = False,
) -> None:
    """Escucha conexiones TCP hasta que se interrumpa el proceso."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((config.host, config.port))
        server.listen()
        LOGGER.info("Servidor TCP escuchando en %s:%s", config.host, config.port)

        while True:
            try:
                connection, address = server.accept()
                LOGGER.info("Conexión aceptada desde %s:%s", *address)
                connection.settimeout(connection_timeout_seconds)
                handle_connection(
                    connection, address, controller, audit_logger, protected_error, ipsec_simulator, ipsec_required,
                    transport_is_tls=False, allow_insecure_tcp_auth=allow_insecure_tcp_auth,
                )
            except OSError as error:
                LOGGER.error("Error al aceptar una conexión: %s", error)


def create_server_tls_context(config: TLSServerConfig) -> ssl.SSLContext:
    """Crea un contexto TLS de servidor con TLS 1.2 como versión mínima."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=config.cert_file, keyfile=config.key_file)
    return context


def _wrap_tls_connection(
    context: ssl.SSLContext,
    connection: socket.socket,
    address: tuple[str, int],
    handshake_timeout_seconds: int,
    audit_logger: AuditLogger | None,
) -> ssl.SSLSocket | None:
    """Limita el handshake TLS y rechaza fallos sin registrar datos del cliente."""
    connection.settimeout(handshake_timeout_seconds)
    try:
        return context.wrap_socket(connection, server_side=True)
    except TimeoutError:
        LOGGER.warning("Tiempo de espera durante handshake TLS desde %s:%s", *address)
        _record_transport_rejection(audit_logger, "tls_handshake_timeout")
    except ssl.SSLError as error:
        LOGGER.warning("Negociación TLS rechazada para %s:%s: %s", *address, error)
        _record_transport_rejection(audit_logger, "tls_handshake_rejected")
    connection.close()
    return None


def serve_tls(
    network_config: TCPConfig,
    tls_config: TLSServerConfig,
    controller: AccessController | None = None,
    audit_logger: AuditLogger | None = None,
    protected_error: str | None = None,
    ipsec_simulator: IPSecSimulator | None = None,
    ipsec_required: bool = False,
    connection_timeout_seconds: int = 10,
    handshake_timeout_seconds: int = 10,
) -> None:
    """Escucha conexiones TLS y procesa el mismo protocolo de mensajes de TCP."""
    context = create_server_tls_context(tls_config)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((network_config.host, network_config.port))
        server.listen()
        LOGGER.info("Servidor TLS escuchando en %s:%s", network_config.host, network_config.port)

        while True:
            connection, address = server.accept()
            LOGGER.info("Conexión TCP aceptada desde %s:%s; iniciando TLS", *address)
            secure_connection = _wrap_tls_connection(
                context, connection, address, handshake_timeout_seconds, audit_logger,
            )
            if secure_connection is None:
                continue
            secure_connection.settimeout(connection_timeout_seconds)
            handle_connection(
                secure_connection, address, controller, audit_logger, protected_error, ipsec_simulator, ipsec_required,
                transport_is_tls=True,
            )


def load_access_control() -> tuple[AccessController | None, str | None]:
    """Carga la seguridad de aplicación; una falla deja las operaciones protegidas cerradas."""
    try:
        config = load_auth_config()
        return AccessController.from_file(config.users_file), None
    except (ValueError, UserStoreError, OSError) as error:
        LOGGER.warning("Operaciones protegidas no disponibles: %s", error)
        return None, "configuración de autenticación no disponible"


def load_audit_logger() -> tuple[AuditLogger | None, str | None]:
    """Inicializa auditoría por separado para registrar rechazos IPSec sin usuarios."""
    try:
        audit_logger = AuditLogger(load_audit_config().audit_log_file)
        audit_logger.ensure_writable()
        return audit_logger, None
    except (ValueError, OSError) as error:
        LOGGER.warning("Auditoría no disponible: %s", error)
        return None, "configuración de auditoría no disponible"


def load_ipsec_simulator() -> tuple[IPSecSimulator | None, bool]:
    """Carga la simulación opcional; ante error, el servidor rechaza sus paquetes."""
    try:
        if not ipsec_simulation_enabled():
            return None, False
        settings = load_ipsec_simulation_settings()
        return IPSecSimulator(IPSecSimulationConfig(**settings.__dict__)), True
    except ValueError as error:
        LOGGER.warning("Simulación de encapsulado no disponible: %s", error)
        return None, True


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        network_config = load_tcp_config()
        transport_security = load_transport_security_config()
        controller, protected_error = load_access_control()
        audit_logger, audit_error = load_audit_logger()
        if protected_error is None and audit_error is not None:
            protected_error = audit_error
        ipsec_simulator, ipsec_required = load_ipsec_simulator()
        if ipsec_required and audit_logger is None:
            raise ValueError("La simulación IPSec requiere AUDIT_LOG_FILE disponible; el servidor no se iniciará.")
        if load_communication_mode() == "tls":
            serve_tls(
                network_config, load_tls_server_config(), controller, audit_logger, protected_error,
                ipsec_simulator, ipsec_required, transport_security.connection_timeout_seconds,
                transport_security.tls_handshake_timeout_seconds,
            )
        else:
            serve(
                network_config, controller, audit_logger, protected_error, ipsec_simulator, ipsec_required,
                transport_security.connection_timeout_seconds, transport_security.allow_insecure_tcp_auth,
            )
    except ValueError as error:
        LOGGER.error("Configuración inválida: %s", error)
    except (OSError, ssl.SSLError) as error:
        LOGGER.error("No se pudo iniciar el servidor: %s", error)
    except KeyboardInterrupt:
        LOGGER.info("Servidor detenido por el usuario.")


if __name__ == "__main__":
    main()
