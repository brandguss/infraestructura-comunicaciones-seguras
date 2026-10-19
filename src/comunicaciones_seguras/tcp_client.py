"""Cliente TCP sencillo para la primera etapa del proyecto."""

from __future__ import annotations

import argparse
import logging
import socket
from typing import Final

from .config import load_tcp_config

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


def main() -> None:
    parser = argparse.ArgumentParser(description="Envía un mensaje a un servidor TCP.")
    parser.add_argument("message", help="Texto UTF-8 que se enviará al servidor.")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    try:
        config = load_tcp_config()
        print(send_message(config.host, config.port, args.message))
    except (ValueError, ConnectionError) as error:
        LOGGER.error("Error del cliente: %s", error)


if __name__ == "__main__":
    main()
