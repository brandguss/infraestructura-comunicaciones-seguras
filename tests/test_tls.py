"""Pruebas TLS con material de PKI externo al repositorio."""

from __future__ import annotations

import os
import socket
import ssl
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.comunicaciones_seguras.config import TLSClientConfig, TLSServerConfig
from src.comunicaciones_seguras.tcp_client import send_tls_message
from src.comunicaciones_seguras.tcp_server import _wrap_tls_connection, create_server_tls_context, handle_connection


class TLSExternalMaterialTests(unittest.TestCase):
    """Pruebas que se omiten claramente si falta PKI externa de desarrollo."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ca_file = Path(os.getenv("TLS_TEST_CA_FILE", ""))
        cls.cert_file = Path(os.getenv("TLS_TEST_CERT_FILE", ""))
        cls.key_file = Path(os.getenv("TLS_TEST_KEY_FILE", ""))
        cls.server_name = os.getenv("TLS_TEST_SERVER_NAME", "localhost")
        missing = [
            variable
            for variable, path in {
                "TLS_TEST_CA_FILE": cls.ca_file,
                "TLS_TEST_CERT_FILE": cls.cert_file,
                "TLS_TEST_KEY_FILE": cls.key_file,
            }.items()
            if not str(path) or not path.is_file()
        ]
        if missing:
            raise unittest.SkipTest(
                "PKI externa no disponible; defina " + ", ".join(missing)
            )

    def _serve_once(self) -> tuple[str, int, threading.Thread]:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        host, port = listener.getsockname()
        context = create_server_tls_context(
            TLSServerConfig(cert_file=self.cert_file, key_file=self.key_file)
        )

        def run_server() -> None:
            connection, address = listener.accept()
            try:
                with context.wrap_socket(connection, server_side=True) as secure_connection:
                    handle_connection(secure_connection, address)
            except (OSError, ssl.SSLError):
                # Los rechazos del cliente son resultados esperados en dos pruebas.
                connection.close()
            finally:
                listener.close()

        thread = threading.Thread(target=run_server)
        thread.start()
        return host, port, thread

    def _client_config(self, ca_file: Path, server_name: str | None = None) -> TLSClientConfig:
        return TLSClientConfig(ca_file=ca_file, server_name=server_name or self.server_name)

    def test_valid_tls_connection(self) -> None:
        host, port, thread = self._serve_once()
        self.assertEqual(
            send_tls_message(host, port, "Prueba TLS válida", self._client_config(self.ca_file)),
            "RECIBIDO: Prueba TLS válida",
        )
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_rejects_untrusted_ca(self) -> None:
        untrusted_ca = Path(os.getenv("TLS_TEST_UNTRUSTED_CA_FILE", ""))
        if not str(untrusted_ca) or not untrusted_ca.is_file():
            self.skipTest("Defina TLS_TEST_UNTRUSTED_CA_FILE con otra CA válida de pruebas.")
        host, port, thread = self._serve_once()
        with self.assertRaises(ssl.SSLCertVerificationError):
            send_tls_message(host, port, "CA no confiable", self._client_config(untrusted_ca))
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_rejects_wrong_hostname(self) -> None:
        host, port, thread = self._serve_once()
        with self.assertRaises(ssl.SSLCertVerificationError):
            send_tls_message(
                host,
                port,
                "Hostname incorrecto",
                self._client_config(self.ca_file, "nombre-invalido.ejemplo"),
            )
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())


class TLSConnectionErrorTests(unittest.TestCase):
    """Pruebas TLS que no requieren certificados."""

    def test_connection_error(self) -> None:
        reserved_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        reserved_socket.bind(("127.0.0.1", 0))
        _, unused_port = reserved_socket.getsockname()
        reserved_socket.close()
        config = TLSClientConfig(ca_file=Path("ca-inexistente.crt"), server_name="localhost")
        with self.assertRaises(ConnectionError):
            send_tls_message("127.0.0.1", unused_port, "Sin servidor", config)

    def test_slow_handshake_is_rejected_without_blocking(self) -> None:
        class SlowContext:
            def wrap_socket(self, connection: socket.socket, *, server_side: bool) -> socket.socket:
                raise TimeoutError("simulated slow handshake")

        client, server = socket.socketpair()
        self.assertIsNone(_wrap_tls_connection(SlowContext(), server, ("local", 0), 1, None))  # type: ignore[arg-type]
        client.close()


if __name__ == "__main__":
    unittest.main()
