"""Servidor TCP sencillo para la primera etapa del proyecto."""

from __future__ import annotations

import logging
import socket
from typing import Final

from .config import TCPConfig, load_tcp_config

BUFFER_SIZE: Final = 4096
LOGGER = logging.getLogger(__name__)


def handle_connection(connection: socket.socket, address: tuple[str, int]) -> None:
    """Procesa un mensaje de un cliente y devuelve una confirmación."""
    try:
        data = connection.recv(BUFFER_SIZE)
        if not data:
            LOGGER.warning("Conexión vacía desde %s:%s", *address)
            return

        message = data.decode("utf-8")
        LOGGER.info("Mensaje recibido de %s:%s", *address)
        connection.sendall(f"RECIBIDO: {message}".encode("utf-8"))
    except UnicodeDecodeError:
        LOGGER.warning("Datos no UTF-8 rechazados desde %s:%s", *address)
        connection.sendall(b"ERROR: el mensaje debe usar UTF-8")
    except OSError as error:
        LOGGER.error("Error con %s:%s: %s", *address, error)
    finally:
        connection.close()
        LOGGER.info("Conexión cerrada con %s:%s", *address)


def serve(config: TCPConfig) -> None:
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
                handle_connection(connection, address)
            except OSError as error:
                LOGGER.error("Error al aceptar una conexión: %s", error)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        serve(load_tcp_config())
    except ValueError as error:
        LOGGER.error("Configuración inválida: %s", error)
    except OSError as error:
        LOGGER.error("No se pudo iniciar el servidor: %s", error)
    except KeyboardInterrupt:
        LOGGER.info("Servidor detenido por el usuario.")


if __name__ == "__main__":
    main()
