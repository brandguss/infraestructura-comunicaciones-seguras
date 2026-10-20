"""Administración remota con OpenSSH y registro de cada intento en la auditoría.

La autenticación y la restricción de usuarios las hace el servidor OpenSSH real (clave pública,
`AllowUsers`, contraseñas desactivadas). Este módulo es el cliente administrativo del proyecto:
solo permite comandos de una lista cerrada, exige verificar la clave del host y deja constancia
de cada intento (aceptado o rechazado) en el mismo registro de auditoría que usa el resto de la
aplicación, sin guardar rutas, claves ni la salida de error de OpenSSH.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from typing import Callable, Final

from .audit import AuditLogger
from .config import SSHIntegrationConfig, load_audit_config, load_ssh_integration_config

ALLOWED_COMMANDS: Final = frozenset({"whoami", "hostname"})


@dataclass(frozen=True)
class SSHResult:
    """Resultado de un intento de administración remota."""

    allowed: bool
    returncode: int
    output: str
    reason: str | None


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


def build_ssh_command(config: SSHIntegrationConfig, remote_command: str) -> list[str]:
    """Construye la orden de OpenSSH: solo clave pública, host verificado y sin preguntas."""
    if remote_command not in ALLOWED_COMMANDS:
        raise ValueError(f"Comando no permitido; use uno de: {', '.join(sorted(ALLOWED_COMMANDS))}.")
    command = [
        config.executable,
        "-o", "BatchMode=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"ConnectTimeout={config.timeout_seconds}",
        "-o", "NumberOfPasswordPrompts=0",
        "-i", str(config.private_key_file),
        "-p", str(config.port),
    ]
    if config.known_hosts_file:
        command.extend(["-o", f"UserKnownHostsFile={config.known_hosts_file}"])
    command.extend([f"{config.user}@{config.host}", remote_command])
    return command


def run_admin_command(
    config: SSHIntegrationConfig,
    remote_command: str,
    audit_logger: AuditLogger | None = None,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> SSHResult:
    """Ejecuta un comando administrativo y registra el intento."""
    command = build_ssh_command(config, remote_command)
    operation = f"ssh:{remote_command}"
    try:
        completed = runner(
            command, capture_output=True, text=True, timeout=config.timeout_seconds + 5, check=False,
        )
    except subprocess.TimeoutExpired:
        result = SSHResult(False, -1, "", "conexión SSH agotó el tiempo límite")
    except OSError:
        result = SSHResult(False, -1, "", "no se pudo ejecutar el cliente SSH")
    else:
        if completed.returncode == 0:
            result = SSHResult(True, 0, completed.stdout.strip(), None)
        else:
            result = SSHResult(False, completed.returncode, "", safe_ssh_failure_reason(completed.stderr))
    if audit_logger is not None:
        audit_logger.record(
            username=config.user,
            operation=operation,
            result="allowed" if result.allowed else "denied",
            reason=result.reason,
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Ejecuta un comando administrativo por SSH y lo audita.")
    parser.add_argument("--command", choices=sorted(ALLOWED_COMMANDS), default="whoami")
    args = parser.parse_args()
    try:
        config = load_ssh_integration_config()
        audit_logger = AuditLogger(load_audit_config().audit_log_file)
    except ValueError as error:
        parser.error(str(error))
    try:
        result = run_admin_command(config, args.command, audit_logger)
    except OSError as error:
        print(f"ERROR: no se pudo escribir la auditoría: {error}", file=sys.stderr)
        return 2
    target = f"{config.user}@{config.host}:{config.port}"
    if result.allowed:
        print(f"ACEPTADO: {target} -> {args.command}: {result.output}")
        return 0
    print(f"RECHAZADO: {target} -> {args.command}: {result.reason}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
