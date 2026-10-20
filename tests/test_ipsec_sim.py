"""Pruebas de la simulación educativa de encapsulado tipo IPSec."""

from __future__ import annotations

import base64
import json
import os
import secrets
import socket
import ssl
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.comunicaciones_seguras.audit import AuditLogger
from src.comunicaciones_seguras.config import TLSClientConfig, TLSServerConfig, load_ipsec_simulation_settings
from src.comunicaciones_seguras.ipsec_key_setup import create_key_file, resolve_external_destination
from src.comunicaciones_seguras.ipsec_sim import (
    IPSecSimulationConfig,
    IPSecSimulator,
    IntegrityError,
    PacketFormatError,
    ReplayError,
)
from src.comunicaciones_seguras.tcp_client import send_tls_message
from src.comunicaciones_seguras.tcp_server import create_server_tls_context, handle_connection


def make_simulator(*, mode: str = "transport", window: int = 64, max_size: int = 2048) -> IPSecSimulator:
    return IPSecSimulator(IPSecSimulationConfig(secrets.token_bytes(32), "test-spi", mode, window, max_size))


class IPSecSimulationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = secrets.token_bytes(32)

    def _pair(self, *, mode: str = "transport", window: int = 64, max_size: int = 2048) -> tuple[IPSecSimulator, IPSecSimulator]:
        config = IPSecSimulationConfig(self.key, "test-spi", mode, window, max_size)
        return IPSecSimulator(config), IPSecSimulator(config)

    def test_transport_and_tunnel_round_trip(self) -> None:
        for mode in ("transport", "tunnel"):
            with self.subTest(mode=mode):
                sender, receiver = self._pair(mode=mode)
                self.assertEqual(receiver.decapsulate(sender.encapsulate("mensaje protegido")), "mensaje protegido")

    def test_tampered_packet_and_wrong_key_are_rejected(self) -> None:
        sender, receiver = self._pair()
        packet = json.loads(sender.encapsulate("integridad"))
        packet["sequence"] = 99
        with self.assertRaises(IntegrityError):
            receiver.decapsulate(json.dumps(packet))
        other_receiver = IPSecSimulator(IPSecSimulationConfig(secrets.token_bytes(32), "test-spi", "transport"))
        with self.assertRaises(IntegrityError):
            other_receiver.decapsulate(sender.encapsulate("clave distinta"))

    def test_invalid_format_and_size_are_rejected(self) -> None:
        _, receiver = self._pair(max_size=8)
        with self.assertRaises(PacketFormatError):
            receiver.decapsulate('{"version":1,"version":1}')
        sender, _ = self._pair(max_size=8)
        with self.assertRaises(PacketFormatError):
            sender.encapsulate("mensaje demasiado largo")

    def test_duplicate_stale_and_out_of_order_sequences(self) -> None:
        sender, receiver = self._pair(window=4)
        first = sender.encapsulate("uno")
        second = sender.encapsulate("dos")
        third = sender.encapsulate("tres")
        self.assertEqual(receiver.decapsulate(first), "uno")
        self.assertEqual(receiver.decapsulate(third), "tres")
        self.assertEqual(receiver.decapsulate(second), "dos")
        with self.assertRaisesRegex(ReplayError, "ipsec_replay_duplicate"):
            receiver.decapsulate(second)
        sender.encapsulate("cuatro")
        sender.encapsulate("cinco")
        sixth = sender.encapsulate("seis")
        receiver.decapsulate(sixth)
        with self.assertRaisesRegex(ReplayError, "ipsec_replay_stale"):
            receiver.decapsulate(first)

    def test_concurrent_duplicate_is_accepted_once(self) -> None:
        sender, receiver = self._pair()
        packet = sender.encapsulate("una vez")
        results: list[str] = []
        lock = threading.Lock()

        def receive() -> None:
            try:
                receiver.decapsulate(packet)
                outcome = "accepted"
            except ReplayError:
                outcome = "replayed"
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=receive) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)
        self.assertEqual(results.count("accepted"), 1)
        self.assertEqual(results.count("replayed"), 7)

    def test_configuration_key_must_be_bytes(self) -> None:
        with self.assertRaises(ValueError):
            IPSecSimulationConfig("x" * 32, "test-spi", "transport")  # type: ignore[arg-type]


class IPSecConfigurationTests(unittest.TestCase):
    def _environment(self, key_path: Path, **extra: str) -> dict[str, str]:
        return {
            "IPSEC_SIM_KEY_FILE": str(key_path),
            "IPSEC_SIM_SPI": "test-spi",
            "IPSEC_SIM_MODE": "transport",
            **extra,
        }

    def test_missing_invalid_and_wrong_length_key_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            cases = {
                "missing.json": None,
                "invalid-base64.json": {"key_b64": "%%%"},
                "wrong-length.json": {"key_b64": "YWJj"},
                "unexpected.json": {"key_b64": "YWJj", "extra": "no"},
            }
            for filename, document in cases.items():
                with self.subTest(filename=filename):
                    path = root / filename
                    if document is not None:
                        path.write_text(json.dumps(document), encoding="utf-8")
                    with patch.dict(os.environ, self._environment(path), clear=False):
                        with self.assertRaises(ValueError):
                            load_ipsec_simulation_settings()

    def test_invalid_simulation_parameters_are_rejected_when_loading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "test-key.json"
            path.write_text(json.dumps({"key_b64": base64.b64encode(secrets.token_bytes(32)).decode("ascii")}), encoding="utf-8")
            with patch.dict(os.environ, self._environment(path, IPSEC_SIM_MODE="not-a-mode"), clear=False):
                with self.assertRaises(ValueError):
                    load_ipsec_simulation_settings()

    def test_key_destination_inside_repository_is_rejected_and_existing_file_is_preserved(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        with self.assertRaises(ValueError):
            resolve_external_destination("relative-key.json", repository)
        with self.assertRaises(ValueError):
            resolve_external_destination(str(repository / "nested" / ".." / "absolute-key.json"), repository)
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "external-key.json"
            create_key_file(destination)
            self.assertTrue(destination.is_file())
            with self.assertRaises(ValueError):
                create_key_file(destination)

    def test_key_destination_resolves_existing_symbolic_components(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repository"
            root.mkdir()
            alias = Path(temporary_directory) / "alias"
            try:
                alias.symlink_to(root, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("El entorno no permite crear enlaces simbólicos para esta comprobación.")
            with self.assertRaises(ValueError):
                resolve_external_destination(str(alias / "key.json"), root)


class IPSecTCPIntegrationTests(unittest.TestCase):
    def test_tcp_decapsulation_and_replay_audit(self) -> None:
        key = secrets.token_bytes(32)
        config = IPSecSimulationConfig(key, "tcp-spi", "transport")
        sender, receiver = IPSecSimulator(config), IPSecSimulator(config)
        with tempfile.TemporaryDirectory() as temporary_directory:
            audit_path = Path(temporary_directory) / "audit.jsonl"
            audit = AuditLogger(audit_path)
            packet = sender.encapsulate("mensaje TCP")

            def exchange(message: str) -> str:
                client, server = socket.socketpair()
                thread = threading.Thread(
                    target=handle_connection,
                    args=(server, ("local", 0)),
                    kwargs={"ipsec_simulator": receiver, "ipsec_required": True, "audit_logger": audit},
                )
                thread.start()
                client.sendall(message.encode("utf-8"))
                response = client.recv(4096).decode("utf-8")
                client.close()
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                return response

            self.assertEqual(exchange(packet), "RECIBIDO: mensaje TCP")
            self.assertEqual(exchange(packet), "ERROR: paquete de simulacion rechazado")
            event = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[-1])
            self.assertEqual(event["reason"], "ipsec_replay_duplicate")
            self.assertNotIn(packet, audit_path.read_text(encoding="utf-8"))

    def test_invalid_and_replayed_packets_do_not_reach_access_controller(self) -> None:
        class User:
            username = "test-user"

        class SentinelController:
            def __init__(self) -> None:
                self.calls = 0

            def execute(self, username: object, password: object, operation: object) -> tuple[object, str]:
                self.calls += 1
                return User(), "operación permitida"

        key = secrets.token_bytes(32)
        config = IPSecSimulationConfig(key, "guard-spi", "transport")
        sender, receiver = IPSecSimulator(config), IPSecSimulator(config)
        controller = SentinelController()

        with tempfile.TemporaryDirectory() as temporary_directory:
            audit = AuditLogger(Path(temporary_directory) / "audit.jsonl")

            def exchange(message: str) -> str:
                client, server = socket.socketpair()
                thread = threading.Thread(
                    target=handle_connection,
                    args=(server, ("local", 0)),
                    kwargs={
    "ipsec_simulator": receiver,
    "ipsec_required": True,
    "controller": controller,
    "audit_logger": audit,
    "allow_insecure_tcp_auth": True,
},
                )
                thread.start()
                client.sendall(message.encode("utf-8"))
                response = client.recv(4096).decode("utf-8")
                client.close()
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                return response

            packet = sender.encapsulate(json.dumps({"username": "x", "password": "x", "operation": "status"}))
            damaged = json.loads(packet)
            damaged["sequence"] = 2
            self.assertEqual(exchange(json.dumps(damaged)), "ERROR: paquete de simulacion rechazado")
            self.assertEqual(controller.calls, 0)

            self.assertEqual(
                exchange(packet),
                '{"result": "ok", "operation": "status", "data": "operación permitida"}',
            )
            self.assertEqual(controller.calls, 1)
            self.assertEqual(exchange(packet), "ERROR: paquete de simulacion rechazado")
            self.assertEqual(controller.calls, 1)


class IPSecTLSIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ca_file = Path(os.getenv("TLS_TEST_CA_FILE", ""))
        cls.cert_file = Path(os.getenv("TLS_TEST_CERT_FILE", ""))
        cls.key_file = Path(os.getenv("TLS_TEST_KEY_FILE", ""))
        missing = [path for path in (cls.ca_file, cls.cert_file, cls.key_file) if not path.is_file()]
        if missing:
            raise unittest.SkipTest("PKI externa no disponible para integración TLS de simulación.")

    def test_tls_decapsulation(self) -> None:
        key = secrets.token_bytes(32)
        config = IPSecSimulationConfig(key, "tls-spi", "tunnel")
        sender, receiver = IPSecSimulator(config), IPSecSimulator(config)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        host, port = listener.getsockname()
        context = create_server_tls_context(TLSServerConfig(self.cert_file, self.key_file))

        def serve_once() -> None:
            connection, address = listener.accept()
            try:
                with context.wrap_socket(connection, server_side=True) as secure_connection:
                    handle_connection(secure_connection, address, ipsec_simulator=receiver, ipsec_required=True)
            finally:
                listener.close()

        thread = threading.Thread(target=serve_once)
        thread.start()
        client_config = TLSClientConfig(self.ca_file, "localhost")
        self.assertEqual(send_tls_message(host, port, sender.encapsulate("mensaje TLS"), client_config), "RECIBIDO: mensaje TLS")
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
