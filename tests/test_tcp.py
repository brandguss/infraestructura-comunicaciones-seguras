"""Pruebas de la primera etapa TCP."""

from __future__ import annotations

import os
import socket
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.comunicaciones_seguras.config import load_tcp_config, load_transport_security_config
from src.comunicaciones_seguras.tcp_client import send_message
from src.comunicaciones_seguras.tcp_server import handle_connection


class TCPTests(unittest.TestCase):
    def test_configuration_uses_environment_values(self) -> None:
        with patch.dict(os.environ, {"TCP_HOST": "192.0.2.10", "TCP_PORT": "6000"}):
            config = load_tcp_config()
        self.assertEqual(config.host, "192.0.2.10")
        self.assertEqual(config.port, 6000)

    def test_configuration_rejects_invalid_port(self) -> None:
        with patch.dict(os.environ, {"TCP_PORT": "70000"}):
            with self.assertRaises(ValueError):
                load_tcp_config()

    def test_transport_security_defaults_and_rejects_invalid_timeout(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(load_transport_security_config().allow_insecure_tcp_auth)
        with patch.dict(os.environ, {"CONNECTION_TIMEOUT_SECONDS": "0"}, clear=True):
            with self.assertRaises(ValueError):
                load_transport_security_config()

    def test_client_and_server_exchange_message(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        host, port = listener.getsockname()

        def run_server() -> None:
            connection, address = listener.accept()
            try:
                handle_connection(connection, address)
            finally:
                listener.close()

        thread = threading.Thread(target=run_server)
        thread.start()
        self.assertEqual(send_message(host, port, "Prueba local"), "RECIBIDO: Prueba local")
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_client_that_sends_no_data_times_out(self) -> None:
        client, server = socket.socketpair()
        server.settimeout(1)
        thread = threading.Thread(target=handle_connection, args=(server, ("local", 0)))
        thread.start()
        self.assertEqual(client.recv(4096), b"ERROR: tiempo de espera de conexion")
        client.close()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
