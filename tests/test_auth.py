"""Pruebas de autenticación, autorización y auditoría sin secretos versionados."""

from __future__ import annotations

import json
import secrets
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.comunicaciones_seguras.audit import AuditLogger
from src.comunicaciones_seguras.auth import AccessController, make_user_record, write_user_store
from src.comunicaciones_seguras.tcp_server import handle_connection


class AccessControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        root = Path(self.temporary_directory.name)
        self.users_file = root / "users.json"
        self.audit_file = root / "audit.jsonl"
        self.passwords = {role: secrets.token_urlsafe(24) for role in ("admin", "operator", "reader")}
        write_user_store(
            self.users_file,
            [
                make_user_record("admin", "administrador", self.passwords["admin"]),
                make_user_record("operator", "operador", self.passwords["operator"]),
                make_user_record("reader", "consulta", self.passwords["reader"]),
            ],
        )
        self.controller = AccessController.from_file(self.users_file)
        self.audit_logger = AuditLogger(self.audit_file)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _request(self, username: str, password: str, operation: str, *, configured: bool = True) -> dict[str, object]:
        client, server = socket.socketpair()
        request = json.dumps(
            {"username": username, "password": password, "operation": operation, "role": "administrador"}
        ).encode("utf-8")
        thread = threading.Thread(
            target=handle_connection,
            args=(server, ("local", 0)),
            kwargs=(
                {"controller": self.controller, "audit_logger": self.audit_logger, "transport_is_tls": True}
                if configured
                else {"protected_error": "archivo ausente", "transport_is_tls": True}
            ),
        )
        thread.start()
        client.sendall(request)
        response = json.loads(client.recv(4096).decode("utf-8"))
        client.close()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        return response

    def test_authentication_accepts_valid_credentials(self) -> None:
        response = self._request("reader", self.passwords["reader"], "status")
        self.assertEqual(response["result"], "ok")
        self.assertEqual(response["operation"], "status")

    def test_invalid_username_and_password_have_same_public_response(self) -> None:
        unknown = self._request("missing", secrets.token_urlsafe(24), "status")
        wrong_password = self._request("reader", secrets.token_urlsafe(24), "status")
        self.assertEqual(unknown, {"result": "denied", "reason": "acceso_denegado"})
        self.assertEqual(wrong_password, unknown)

    def test_permissions_are_determined_by_server_role(self) -> None:
        self.assertEqual(self._request("admin", self.passwords["admin"], "admin_info")["result"], "ok")
        self.assertEqual(self._request("operator", self.passwords["operator"], "list_resources")["result"], "ok")
        denied = self._request("reader", self.passwords["reader"], "admin_info")
        self.assertEqual(denied, {"result": "denied", "reason": "acceso_denegado"})

    def test_client_role_is_not_trusted(self) -> None:
        denied = self._request("reader", self.passwords["reader"], "admin_info")
        self.assertEqual(denied["result"], "denied")

    def test_missing_configuration_fails_closed(self) -> None:
        response = self._request("reader", self.passwords["reader"], "status", configured=False)
        self.assertEqual(response, {"result": "denied", "reason": "servicio_no_disponible"})

    def test_tcp_rejects_protected_operation_without_laboratory_opt_in(self) -> None:
        response = self._request("reader", self.passwords["reader"], "status", configured=True)
        # El helper representa TLS; la comprobación TCP se ejercita directamente a continuación.
        client, server = socket.socketpair()
        request = json.dumps({"username": "reader", "password": self.passwords["reader"], "operation": "status"}).encode("utf-8")
        thread = threading.Thread(target=handle_connection, args=(server, ("local", 0)), kwargs={"controller": self.controller, "audit_logger": self.audit_logger})
        thread.start()
        client.sendall(request)
        rejected = json.loads(client.recv(4096).decode("utf-8"))
        client.close()
        thread.join(timeout=2)
        self.assertEqual(rejected, {"result": "denied", "reason": "canal_inseguro"})
        self.assertEqual(response["result"], "ok")

    def test_tcp_laboratory_opt_in_allows_protected_operation(self) -> None:
        client, server = socket.socketpair()
        request = json.dumps({"username": "reader", "password": self.passwords["reader"], "operation": "status"}).encode("utf-8")
        thread = threading.Thread(
            target=handle_connection,
            args=(server, ("local", 0)),
            kwargs={"controller": self.controller, "audit_logger": self.audit_logger, "allow_insecure_tcp_auth": True},
        )
        thread.start()
        client.sendall(request)
        response = json.loads(client.recv(4096).decode("utf-8"))
        client.close()
        thread.join(timeout=2)
        self.assertEqual(response["result"], "ok")

    def test_audit_log_is_structured_and_redacts_secrets(self) -> None:
        self._request("reader", self.passwords["reader"], "status")
        self._request("reader", self.passwords["reader"], "admin_info")
        events = [json.loads(line) for line in self.audit_file.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([event["result"] for event in events], ["allowed", "denied"])
        self.assertEqual(events[1]["reason"], "permiso_insuficiente")
        stored_users = json.loads(self.users_file.read_text(encoding="utf-8"))["users"]
        self.assertNotIn(self.passwords["reader"], self.audit_file.read_text(encoding="utf-8"))
        self.assertNotIn(stored_users[2]["password_hash"], self.audit_file.read_text(encoding="utf-8"))
        self.assertNotIn(stored_users[2]["salt"], self.audit_file.read_text(encoding="utf-8"))
        self.assertTrue(all({"timestamp", "username", "operation", "result", "reason"} <= event.keys() for event in events))


if __name__ == "__main__":
    unittest.main()
