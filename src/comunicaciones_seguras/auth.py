"""Autenticación y autorización de operaciones de demostración."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Final

SCRYPT_N: Final = 2**14
SCRYPT_R: Final = 8
SCRYPT_P: Final = 1
SCRYPT_DKLEN: Final = 64
ROLES: Final = {"administrador", "operador", "consulta"}
PERMISSIONS: Final = {
    "administrador": frozenset({"status", "list_resources", "admin_info"}),
    "operador": frozenset({"status", "list_resources"}),
    "consulta": frozenset({"status"}),
}
OPERATION_RESULTS: Final = {
    "status": "Servicio disponible.",
    "list_resources": "Recursos: comunicaciones, PKI, auditoría.",
    "admin_info": "Información administrativa disponible.",
}
DUMMY_SALT: Final = b"credencial-invalida-scrypt"
DUMMY_HASH: Final = hashlib.scrypt(
    b"credencial-invalida", salt=DUMMY_SALT, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN
)


class AuthenticationError(Exception):
    """Credenciales que no deben revelar cuál de sus campos fue incorrecto."""


class AuthorizationError(Exception):
    """Usuario autenticado sin permiso para una operación."""


class UserStoreError(Exception):
    """Archivo de usuarios ausente, ilegible o con formato inseguro."""


@dataclass(frozen=True)
class UserRecord:
    username: str
    role: str
    salt: bytes
    password_hash: bytes


def hash_password(password: str, salt: bytes) -> bytes:
    """Deriva una clave de contraseña con scrypt y parámetros conservadores."""
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN
    )


def make_user_record(username: str, role: str, password: str) -> dict[str, str]:
    """Crea una entrada serializable con sal aleatoria; no imprime secretos."""
    if not username or role not in ROLES or not password:
        raise ValueError("Usuario, rol y contraseña son obligatorios.")
    salt = secrets.token_bytes(16)
    return {
        "username": username,
        "role": role,
        "salt": salt.hex(),
        "password_hash": hash_password(password, salt).hex(),
    }


def write_user_store(path: Path, records: list[dict[str, str]]) -> None:
    """Escribe el almacén de usuarios externo con permisos del sistema operativo."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"users": records}, indent=2), encoding="utf-8")


class AccessController:
    """Fuente de verdad del servidor para identidad, rol y permisos."""

    def __init__(self, users: dict[str, UserRecord]) -> None:
        self._users = users

    @classmethod
    def from_file(cls, path: Path) -> "AccessController":
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            entries = document["users"]
            if not isinstance(entries, list):
                raise ValueError("users no es una lista")
            users: dict[str, UserRecord] = {}
            for entry in entries:
                username = entry["username"]
                role = entry["role"]
                salt = bytes.fromhex(entry["salt"])
                password_hash = bytes.fromhex(entry["password_hash"])
                if not isinstance(username, str) or not username or role not in ROLES:
                    raise ValueError("entrada de usuario inválida")
                if len(salt) < 16 or len(password_hash) != SCRYPT_DKLEN or username in users:
                    raise ValueError("material de credencial inválido")
                users[username] = UserRecord(username, role, salt, password_hash)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise UserStoreError("No se pudo cargar el almacén externo de usuarios.") from error
        return cls(users)

    def authenticate(self, username: object, password: object) -> UserRecord:
        """Valida credenciales sin distinguir al exterior usuario de contraseña erróneos."""
        user = self._users.get(username) if isinstance(username, str) else None
        supplied = password if isinstance(password, str) else ""
        salt = user.salt if user else DUMMY_SALT
        expected_hash = user.password_hash if user else DUMMY_HASH
        valid = hmac.compare_digest(hash_password(supplied, salt), expected_hash)
        if not user or not valid:
            raise AuthenticationError("Credenciales inválidas.")
        return user

    def execute(self, username: object, password: object, operation: object) -> tuple[UserRecord, str]:
        """Autentica y verifica permisos exclusivamente con el almacén del servidor."""
        user = self.authenticate(username, password)
        if not isinstance(operation, str) or operation not in PERMISSIONS[user.role]:
            raise AuthorizationError("Operación no autorizada.")
        return user, OPERATION_RESULTS[operation]
