"""Crea una asociación simulada externa con una clave aleatoria de 32 bytes."""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
from pathlib import Path


def repository_root() -> Path:
    """Devuelve la raíz del proyecto, resolviendo enlaces existentes."""
    return Path(__file__).resolve().parents[2]


def resolve_external_destination(destination: str, root: Path | None = None) -> Path:
    """Resuelve una ruta y rechaza cualquier destino dentro del repositorio."""
    try:
        resolved_root = (root or repository_root()).resolve(strict=False)
        resolved_path = Path(destination).expanduser().resolve(strict=False)
    except OSError as error:
        raise ValueError("No se pudo resolver la ruta externa de la clave.") from error
    if resolved_path.is_relative_to(resolved_root):
        raise ValueError("IPSEC_SIM_KEY_FILE debe estar fuera del repositorio.")
    return resolved_path


def create_key_file(path: Path) -> None:
    """Crea una clave nueva con apertura exclusiva; nunca reemplaza un archivo."""
    material = json.dumps(
        {"key_b64": base64.b64encode(secrets.token_bytes(32)).decode("ascii")},
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise ValueError("El archivo de clave ya existe y no se reemplazará.") from error
    except PermissionError as error:
        raise ValueError("Permiso denegado al crear el archivo externo de clave.") from error
    except OSError as error:
        raise ValueError("No se pudo crear el archivo externo de clave.") from error
    try:
        with os.fdopen(descriptor, "wb") as key_file:
            key_file.write(material)
    except OSError as error:
        try:
            path.unlink()
        except OSError:
            pass
        raise ValueError("No se pudo escribir el archivo externo de clave.") from error


def main() -> None:
    parser = argparse.ArgumentParser(description="Crea una clave externa para la simulación educativa IPSec.")
    parser.parse_args()
    destination = os.getenv("IPSEC_SIM_KEY_FILE", "").strip()
    if not destination:
        parser.error("Defina IPSEC_SIM_KEY_FILE fuera del repositorio.")
    try:
        path = resolve_external_destination(destination)
        create_key_file(path)
    except ValueError as error:
        parser.error(str(error))
    print(f"Material de simulación creado en {path}.")


if __name__ == "__main__":
    main()
