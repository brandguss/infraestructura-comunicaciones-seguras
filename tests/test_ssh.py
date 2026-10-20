"""Pruebas SSH: lógica local siempre activa e integración real opcional contra OpenSSH."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.comunicaciones_seguras.audit import AuditLogger
from src.comunicaciones_seguras.config import SSHIntegrationConfig, load_ssh_integration_config
from src.comunicaciones_seguras.ssh_admin import (
    build_ssh_command,
    run_admin_command,
    safe_ssh_failure_reason,
)


class SSHConfigurationTests(unittest.TestCase):
    def test_loads_external_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            key_path = Path(temporary_directory) / "external-key-path"
            environment = {
                "SSH_TEST_HOST": "localhost",
                "SSH_TEST_USER": "testuser",
                "SSH_TEST_PRIVATE_KEY_FILE": str(key_path),
                "SSH_TEST_PORT": "2222",
                "SSH_TEST_TIMEOUT": "12",
                "SSH_EXECUTABLE": "ssh",
            }
            with patch.dict(os.environ, environment, clear=True):
                config = load_ssh_integration_config()
        self.assertEqual(config.host, "localhost")
        self.assertEqual(config.user, "testuser")
        self.assertEqual(config.port, 2222)
        self.assertEqual(config.timeout_seconds, 12)

    def test_rejects_missing_key_path(self) -> None:
        with patch.dict(os.environ, {"SSH_TEST_HOST": "localhost", "SSH_TEST_USER": "testuser"}, clear=True):
            with self.assertRaises(ValueError):
                load_ssh_integration_config()

    def test_rejects_ssh_option_in_host_or_user(self) -> None:
        base_environment = {
            "SSH_TEST_HOST": "localhost",
            "SSH_TEST_USER": "testuser",
            "SSH_TEST_PRIVATE_KEY_FILE": "external-key",
        }
        for variable, unsafe_value in (("SSH_TEST_HOST", "-oStrictHostKeyChecking=no"), ("SSH_TEST_USER", "-oProxyCommand=x")):
            with self.subTest(variable=variable):
                environment = {**base_environment, variable: unsafe_value}
                with patch.dict(os.environ, environment, clear=True):
                    with self.assertRaises(ValueError):
                        load_ssh_integration_config()

    def test_redacts_sensitive_ssh_errors(self) -> None:
        self.assertEqual(
            safe_ssh_failure_reason("Load key C:\\Users\\example\\.ssh\\id_ed25519: Permission denied"),
            "clave privada no disponible para el proceso",
        )


def fake_config(directory: str) -> SSHIntegrationConfig:
    return SSHIntegrationConfig(
        executable="ssh", host="servidor-lab", user="admin-lab",
        private_key_file=Path(directory) / "clave-externa", port=22, timeout_seconds=10, known_hosts_file=None,
    )


def fake_runner(returncode: int, stdout: str = "", stderr: str = ""):
    def run(command, **kwargs):  # noqa: ANN001 - firma compatible con subprocess.run
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)
    return run


class SSHAdminClientTests(unittest.TestCase):
    """Comprueban restricciones y registro de intentos sin necesitar un servidor SSH."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = fake_config(self.directory.name)
        self.audit_path = Path(self.directory.name) / "audit.jsonl"
        self.audit = AuditLogger(self.audit_path)

    def events(self) -> list[dict[str, object]]:
        return [json.loads(line) for line in self.audit_path.read_text(encoding="utf-8").splitlines()]

    def test_command_forces_key_authentication_and_host_verification(self) -> None:
        command = build_ssh_command(self.config, "whoami")
        for option in ("BatchMode=yes", "PasswordAuthentication=no", "StrictHostKeyChecking=yes"):
            self.assertIn(option, command)
        self.assertEqual(command[-2:], ["admin-lab@servidor-lab", "whoami"])

    def test_only_allowed_commands_can_be_run(self) -> None:
        for unsafe in ("rm -rf /", "whoami; hostname", "cmd /c dir", ""):
            with self.subTest(command=unsafe), self.assertRaises(ValueError):
                build_ssh_command(self.config, unsafe)

    def test_authorized_access_is_audited_as_allowed(self) -> None:
        result = run_admin_command(self.config, "whoami", self.audit, runner=fake_runner(0, "admin-lab\n"))
        self.assertTrue(result.allowed)
        self.assertEqual(result.output, "admin-lab")
        event = self.events()[-1]
        self.assertEqual((event["username"], event["operation"], event["result"]), ("admin-lab", "ssh:whoami", "allowed"))

    def test_unauthorized_access_is_audited_as_denied_without_leaking_details(self) -> None:
        stderr = "Load key C:\\Users\\privado\\id: ok\nadmin-lab@servidor-lab: Permission denied (publickey)."
        result = run_admin_command(self.config, "whoami", self.audit, runner=fake_runner(255, "", stderr))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "clave privada no disponible para el proceso")
        event = self.events()[-1]
        self.assertEqual(event["result"], "denied")
        self.assertNotIn("privado", self.audit_path.read_text(encoding="utf-8"))

    def test_rejected_public_key_is_classified_and_audited(self) -> None:
        result = run_admin_command(
            self.config, "hostname", self.audit,
            runner=fake_runner(255, "", "admin-lab@servidor-lab: Permission denied (publickey)."),
        )
        self.assertEqual(result.reason, "autenticación por clave rechazada")
        self.assertEqual(self.events()[-1]["reason"], "autenticación por clave rechazada")

    def test_timeout_is_a_denied_attempt(self) -> None:
        def slow(command, **kwargs):  # noqa: ANN001
            raise subprocess.TimeoutExpired(command, 1)

        result = run_admin_command(self.config, "whoami", self.audit, runner=slow)
        self.assertFalse(result.allowed)
        self.assertEqual(self.events()[-1]["result"], "denied")

    def test_each_attempt_adds_one_audit_event(self) -> None:
        run_admin_command(self.config, "whoami", self.audit, runner=fake_runner(0, "x"))
        run_admin_command(self.config, "whoami", self.audit, runner=fake_runner(255, "", "Permission denied"))
        self.assertEqual([event["result"] for event in self.events()], ["allowed", "denied"])


class SSHIntegrationTests(unittest.TestCase):
    """Solo se ejecutan al definir explícitamente SSH_TEST_ENABLED=1."""

    @classmethod
    def setUpClass(cls) -> None:
        if os.getenv("SSH_TEST_ENABLED") != "1":
            raise unittest.SkipTest("Prueba SSH deshabilitada; defina SSH_TEST_ENABLED=1 para ejecutarla.")
        try:
            cls.config = load_ssh_integration_config()
        except ValueError as error:
            raise AssertionError(f"SSH está habilitado pero su configuración es inválida: {error}") from error
        if not shutil.which(cls.config.executable):
            raise AssertionError("SSH está habilitado pero SSH_EXECUTABLE no está disponible.")

    def test_remote_whoami(self) -> None:
        command = [
            self.config.executable,
            "-v",
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"ConnectTimeout={self.config.timeout_seconds}",
            "-o", "NumberOfPasswordPrompts=0",
            "-i", str(self.config.private_key_file),
            "-p", str(self.config.port),
        ]
        if self.config.known_hosts_file:
            command.extend(["-o", f"UserKnownHostsFile={self.config.known_hosts_file}"])
        command.extend([f"{self.config.user}@{self.config.host}", "whoami"])
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds + 5,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            self.fail(f"La conexión SSH excedió el límite de tiempo: {error.timeout} segundos.")
        self.assertEqual(completed.returncode, 0, f"El comando SSH falló: {safe_ssh_failure_reason(completed.stderr)}.")
        self.assertTrue(completed.stdout.strip(), "El comando remoto whoami no devolvió un usuario.")

    def _run_ssh(self, user: str, key_file: str) -> subprocess.CompletedProcess[str]:
        command = [
            self.config.executable, "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
            "-o", "StrictHostKeyChecking=yes", "-o", f"ConnectTimeout={self.config.timeout_seconds}",
            "-i", key_file, "-p", str(self.config.port),
        ]
        if self.config.known_hosts_file:
            command.extend(["-o", f"UserKnownHostsFile={self.config.known_hosts_file}"])
        command.extend([f"{user}@{self.config.host}", "whoami"])
        return subprocess.run(
            command, capture_output=True, text=True, timeout=self.config.timeout_seconds + 5, check=False,
        )

    def test_unauthorized_key_is_rejected(self) -> None:
        key_file = os.getenv("SSH_TEST_UNAUTHORIZED_KEY_FILE", "").strip()
        if not key_file:
            self.skipTest("Defina SSH_TEST_UNAUTHORIZED_KEY_FILE con una clave que NO esté autorizada.")
        completed = self._run_ssh(self.config.user, key_file)
        self.assertNotEqual(completed.returncode, 0, "El servidor aceptó una clave no autorizada.")
        self.assertEqual(safe_ssh_failure_reason(completed.stderr), "autenticación por clave rechazada")

    def test_user_outside_allowed_list_is_rejected(self) -> None:
        user = os.getenv("SSH_TEST_UNAUTHORIZED_USER", "").strip()
        if not user or user.startswith("-") or "@" in user:
            self.skipTest("Defina SSH_TEST_UNAUTHORIZED_USER con una cuenta que no esté en AllowUsers.")
        completed = self._run_ssh(user, str(self.config.private_key_file))
        self.assertNotEqual(completed.returncode, 0, "El servidor aceptó a un usuario no autorizado.")
        self.assertEqual(safe_ssh_failure_reason(completed.stderr), "autenticación por clave rechazada")


if __name__ == "__main__":
    unittest.main()
