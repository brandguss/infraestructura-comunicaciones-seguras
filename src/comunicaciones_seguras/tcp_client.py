"""Cliente TCP sencillo para la primera etapa del proyecto."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import socket
import ssl
from typing import Final

from .config import (
    TLSClientConfig,
    load_communication_mode,
    load_tcp_config,
    load_tls_client_config,
)

BUFFER_SIZE: Final = 4096
TIMEOUT_SECONDS: Final = 5
LOGGER = logging.getLogger(__name__)


def send_message(host: str, port: int, message: str) -> str:
    """Envía un mensaje UTF-8 y devuelve la respuesta del servidor."""
    if not message:
        raise ValueError("El mensaje no puede estar vacío.")

    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS) as connection:
            LOGGER.info("Conectado a %s:%s", host, port)
            connection.sendall(message.encode("utf-8"))
            response = connection.recv(BUFFER_SIZE)
    except (TimeoutError, ConnectionError, OSError) as error:
        raise ConnectionError(f"No fue posible conectar con {host}:{port}: {error}") from error

    if not response:
        raise ConnectionError("El servidor cerró la conexión sin responder.")
    return response.decode("utf-8")


def create_client_tls_context(config: TLSClientConfig) -> ssl.SSLContext:
    """Crea un contexto que confía solo en la CA indicada y valida el nombre."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=config.ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    return context


def send_tls_message(
    host: str, port: int, message: str, tls_config: TLSClientConfig
) -> str:
    """Envía un mensaje sobre TLS con validación obligatoria del servidor."""
    if not message:
        raise ValueError("El mensaje no puede estar vacío.")

    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS) as connection:
            context = create_client_tls_context(tls_config)
            with context.wrap_socket(connection, server_hostname=tls_config.server_name) as secure_connection:
                LOGGER.info("Conexión TLS validada con %s:%s", host, port)
                secure_connection.sendall(message.encode("utf-8"))
                response = secure_connection.recv(BUFFER_SIZE)
    except ssl.SSLError:
        raise
    except (TimeoutError, ConnectionError, OSError) as error:
        raise ConnectionError(f"No fue posible conectar con {host}:{port}: {error}") from error

    if not response:
        raise ConnectionError("El servidor TLS cerró la conexión sin responder.")
    return response.decode("utf-8")


def build_authenticated_request(username: str, password: str, operation: str) -> str:
    """Construye una solicitud sin rol: el servidor decide todos los permisos."""
    if not username or not password or not operation:
        raise ValueError("Usuario, contraseña y operación son obligatorios.")
    return json.dumps({"username": username, "password": password, "operation": operation})


def main() -> None:
    parser = argparse.ArgumentParser(description="Envía un mensaje a un servidor TCP.")
    parser.add_argument("message", nargs="?", help="Texto para el modo de eco compatible.")
    parser.add_argument("--username", help="Usuario para una operación protegida.")
    parser.add_argument("--operation", choices=("status", "list_resources", "admin_info"))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    try:
        if bool(args.username) != bool(args.operation):
            parser.error("Use --username y --operation juntos.")
        message = args.message
        if args.operation:
            message = build_authenticated_request(args.username, getpass.getpass("Contraseña: "), args.operation)
        if not message:
            parser.error("Indique un mensaje o una operación protegida.")
        network_config = load_tcp_config()
        if load_communication_mode() == "tls":
            print(send_tls_message(
                network_config.host,
                network_config.port,
                message,
                load_tls_client_config(),
            ))
        else:
            print(send_message(network_config.host, network_config.port, message))
    except (ValueError, ConnectionError, OSError, ssl.SSLError) as error:
        LOGGER.error("Error del cliente: %s", error)


if __name__ == "__main__":
    main()
