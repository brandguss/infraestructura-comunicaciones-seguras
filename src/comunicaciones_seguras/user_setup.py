"""Crea usuarios de demostración en un archivo externo, sin texto plano persistente."""

from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path

from .auth import make_user_record, write_user_store


def main() -> None:
    parser = argparse.ArgumentParser(description="Crea usuarios de demostración con hashes scrypt.")
    parser.add_argument("--overwrite", action="store_true", help="Permite reemplazar el archivo externo.")
    args = parser.parse_args()
    destination = os.getenv("AUTH_USERS_FILE", "").strip()
    if not destination:
        parser.error("Defina AUTH_USERS_FILE fuera del repositorio.")
    path = Path(destination)
    if path.exists() and not args.overwrite:
        parser.error("El archivo ya existe; use --overwrite solo si desea reemplazarlo.")

    records = []
    for username, role in (("admin", "administrador"), ("operador", "operador"), ("consulta", "consulta")):
        password = getpass.getpass(f"Contraseña para {username} ({role}): ")
        confirmation = getpass.getpass("Repita la contraseña: ")
        if not password or password != confirmation:
            parser.error(f"La contraseña para {username} es vacía o no coincide.")
        records.append(make_user_record(username, role, password))
    write_user_store(path, records)
    print(f"Usuarios de demostración creados en {path}.")


if __name__ == "__main__":
    main()
