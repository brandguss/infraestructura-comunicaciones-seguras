"""Pruebas seguras, opcionales y reales contra OpenSSH externo."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.comunicaciones_seguras.config import load_ssh_integration_config


def safe_ssh_failure_reason(stderr: str) -> str:
    """Resume fallos de OpenSSH sin incluir rutas, claves ni salida del servidor."""
    normalized = stderr.lower()
    if "host key verification failed" in normalized:
        return "verificación de clave de host fallida"
    if "load key" in normalized or "identity file" in normalized or "no such file" in normalized:
        return "clave privada no disponible para el proceso"
    if "sign_and_send_pubkey: signing failed" in normalized or "agent refused operation" in normalized:
        return "el agente o la firma de la clave privada falló"
    if "permission denied" in normalized:
        return "autenticación por clave rechazada"
    if "connection refused" in normalized:
        return "conexión SSH rechazada"
    if "timed out" in normalized:
        return "conexión SSH agotó el tiempo límite"
    return "fallo SSH no clasificado; revise la configuración local"


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


if __name__ == "__main__":
    unittest.main()
