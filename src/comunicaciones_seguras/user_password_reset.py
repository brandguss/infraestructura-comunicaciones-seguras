"""Restablece la contraseña de una sola cuenta sin reemplazar el almacén de usuarios."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
from datetime import datetime
from pathlib import Path

from .auth import make_user_record


def reset_password(path: Path, username: str, password: str) -> Path:
    """Actualiza una cuenta, conserva las demás y crea una copia de respaldo."""
    if not username or not password:
        raise ValueError("El usuario y la contraseña son obligatorios.")
    if not path.is_file():
        raise FileNotFoundError(f"No existe el almacén de usuarios: {path}")

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("No se pudo leer el almacén de usuarios; no se modificó.") from error

    if not isinstance(document, dict) or not isinstance(document.get("users"), list):
        raise ValueError("El almacén no tiene el formato esperado; no se modificó.")

    records = document["users"]
    matches = [
        index for index, record in enumerate(records)
        if isinstance(record, dict) and record.get("username") == username
    ]
    if len(matches) != 1:
        raise ValueError(
            "Debe existir exactamente una cuenta con ese nombre; no se modificó el almacén."
        )

    index = matches[0]
    old_record = records[index]
    role = old_record.get("role")
    replacement = make_user_record(username, role, password)
    new_records = list(records)
    new_records[index] = replacement
    new_document = json.dumps({"users": new_records}, indent=2, ensure_ascii=False) + "\n"

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup = path.with_name(f"{path.name}.{stamp}.bak")
    temporary = path.with_name(f".{path.name}.{stamp}.tmp")
    try:
        shutil.copy2(path, backup)
        temporary.write_text(new_document, encoding="utf-8")
        os.replace(temporary, path)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return backup


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cambia la contraseña de una cuenta sin reemplazar las demás."
    )
    parser.add_argument("--username", default="admin", help="Cuenta que se actualizará (por defecto: admin).")
    args = parser.parse_args()

    destination = os.getenv("AUTH_USERS_FILE", "").strip()
    if not destination:
        parser.error("Defina AUTH_USERS_FILE con la ruta externa a users.json.")

    path = Path(destination)
    password = getpass.getpass(f"Nueva contraseña para {args.username}: ")
    confirmation = getpass.getpass("Repita la nueva contraseña: ")
    if not password or password != confirmation:
        parser.error("La contraseña está vacía o las confirmaciones no coinciden.")

    try:
        backup = reset_password(path, args.username, password)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(f"Contraseña actualizada para '{args.username}'.")
    print(f"Respaldo creado: {backup}")


if __name__ == "__main__":
    main()
