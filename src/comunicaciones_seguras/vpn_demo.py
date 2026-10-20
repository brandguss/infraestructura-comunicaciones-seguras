"""Demostración de la VPN de acceso remoto y la VPN sitio a sitio simuladas.

Uso:  python -m src.comunicaciones_seguras.vpn_demo

Crea usuarios temporales en memoria (las contraseñas de este script son solo de demostración y
no se guardan en ningún archivo). Si AUDIT_LOG_FILE está definida, los eventos se agregan a ese
registro; si no, se usa un archivo temporal que se elimina al terminar.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from pathlib import Path

from .audit import AuditLogger
from .auth import AccessController, UserRecord, hash_password
from .vpn_sim import (
    SCENARIO_COMPARISON,
    RemoteAccessGateway,
    Site,
    SiteToSiteVPN,
    TunnelPacket,
    VPNAccessDenied,
)

DEMO_USERS = (
    ("admin", "administrador", "demo-admin-2026"),
    ("operador", "operador", "demo-operador-2026"),
    ("consulta", "consulta", "demo-consulta-2026"),
)


def _title(text: str) -> None:
    print(f"\n{'=' * 78}\n{text}\n{'=' * 78}")


def _attempt(description: str, action) -> object | None:  # noqa: ANN001
    """Ejecuta una acción y muestra si fue aceptada o rechazada, con el motivo registrado."""
    try:
        outcome = action()
    except VPNAccessDenied as error:
        print(f"  RECHAZADO  {description}  [motivo: {error.reason}]")
        return None
    print(f"  ACEPTADO   {description}")
    return outcome


def _controller() -> AccessController:
    users = {}
    for name, role, password in DEMO_USERS:
        salt = secrets.token_bytes(16)
        users[name] = UserRecord(name, role, salt, hash_password(password, salt))
    return AccessController(users)


def demo_remote_access(audit: AuditLogger) -> None:
    _title("VPN DE ACCESO REMOTO: un usuario entra a la red privada")
    gateway = RemoteAccessGateway(_controller(), audit, max_failed_attempts=3, lockout_seconds=60)

    print("\n1) Autenticación: quién eres")
    _attempt("usuario 'admin' con contraseña incorrecta", lambda: gateway.connect("admin", "incorrecta", "203.0.113.10"))
    consulta = _attempt(
        "usuario 'consulta' con credenciales válidas",
        lambda: gateway.connect("consulta", "demo-consulta-2026", "203.0.113.20"),
    )
    if consulta:
        print(f"             IP virtual asignada: {consulta.virtual_ip} (rol: {consulta.role})")

        print("\n2) Autorización: conectarse NO da acceso a todo; depende del rol")
        print(f"  Recursos que el rol permite: {', '.join(gateway.resources_for(consulta.session_id))}")
        for resource in ("intranet-web", "servidor-archivos", "panel-administracion"):
            _attempt(f"'consulta' intenta usar {resource}", lambda r=resource: gateway.access(consulta.session_id, r))

    print("\n   Otro rol (administrador): acceso más amplio y revocación de la sesión")
    admin = _attempt("usuario 'admin' con credenciales válidas", lambda: gateway.connect("admin", "demo-admin-2026", "203.0.113.30"))
    if admin:
        print(f"             IP virtual asignada: {admin.virtual_ip} (rol: {admin.role})")
        _attempt("'admin' usa panel-administracion", lambda: gateway.access(admin.session_id, "panel-administracion"))
        _attempt("'admin' usa base-datos", lambda: gateway.access(admin.session_id, "base-datos"))
        gateway.disconnect(admin.session_id)
        print("  'admin' se desconecta; la sesión queda revocada")
        _attempt("'admin' reutiliza la sesión cerrada", lambda: gateway.access(admin.session_id, "base-datos"))

    print("\n3) Protección contra adivinar contraseñas")
    for attempt in range(1, 4):
        _attempt(f"intento {attempt} con contraseña incorrecta para 'operador'", lambda: gateway.connect("operador", "mala", "203.0.113.40"))
    _attempt("'operador' con la contraseña CORRECTA durante el bloqueo", lambda: gateway.connect("operador", "demo-operador-2026", "203.0.113.40"))


def demo_site_to_site(audit: AuditLogger) -> None:
    _title("VPN SITIO A SITIO: dos redes conectadas por sus gateways")
    vpn = SiteToSiteVPN(
        Site("Oficina central", "10.10.0.0/24"), Site("Sucursal", "10.20.0.0/24"), secrets.token_bytes(32), audit,
    )
    print("\n1) Tráfico entre redes (sin iniciar sesión: los equipos usan el túnel de forma transparente)")
    packet = _attempt("10.10.0.5 -> 10.20.0.7 (Oficina central a Sucursal)", lambda: vpn.send("10.10.0.5", "10.20.0.7", "consulta de inventario"))
    if packet:
        outer = json.loads(packet.wire)
        print(f"             modo del paquete: {outer['mode']}; encabezado externo: {outer['outer']}; SPI: {outer['spi']}; secuencia: {outer['sequence']}")
        delivered = _attempt("el gateway de la Sucursal entrega el paquete", lambda: vpn.receive(packet))
        if delivered:
            print(f"             entregado a {delivered['destination']}: {delivered['data']!r}")
    reply = _attempt("10.20.0.7 -> 10.10.0.5 (respuesta, sentido contrario)", lambda: vpn.send("10.20.0.7", "10.10.0.5", "respuesta"))
    if reply:
        _attempt("el gateway de la Oficina central entrega la respuesta", lambda: vpn.receive(reply))

    print("\n2) Ataques contra el túnel")
    if packet:
        _attempt("REPLAY: un atacante reenvía el paquete capturado", lambda: vpn.receive(packet))
        forged = json.loads(packet.wire)
        forged["inner"]["payload_b64"] = "bWFsaWNpb3Nv"
        _attempt("MODIFICACIÓN: se altera el contenido del paquete", lambda: vpn.receive(TunnelPacket(packet.direction, json.dumps(forged))))
    attacker = SiteToSiteVPN(Site("Oficina central", "10.10.0.0/24"), Site("Sucursal", "10.20.0.0/24"), secrets.token_bytes(32), audit)
    injected = attacker.send("10.10.0.5", "10.20.0.7", "inyectado")
    _attempt("INYECCIÓN: un gateway con otra clave envía un paquete", lambda: vpn.receive(injected))

    print("\n3) Política de subredes")
    _attempt("10.10.0.5 -> 8.8.8.8 (destino fuera de las dos redes)", lambda: vpn.send("10.10.0.5", "8.8.8.8", "x"))
    _attempt("192.168.1.9 -> 10.20.0.7 (origen que no pertenece a ningún sitio)", lambda: vpn.send("192.168.1.9", "10.20.0.7", "x"))


def print_comparison() -> None:
    _title("COMPARACIÓN: acceso remoto frente a sitio a sitio")
    width = max(len(aspect) for aspect, _, _ in SCENARIO_COMPARISON)
    for aspect, remote, site in SCENARIO_COMPARISON:
        print(f"{aspect:<{width}}\n  Acceso remoto: {remote}\n  Sitio a sitio: {site}")


def print_audit(path: Path, start: int) -> None:
    _title("REGISTRO DE AUDITORÍA (eventos generados por esta demostración)")
    lines = path.read_text(encoding="utf-8").splitlines()[start:]
    for line in lines:
        event = json.loads(line)
        print(f"{event['timestamp'][11:19]}  {str(event['username']):<10} {event['operation']:<34} {event['result']:<8} {event['reason'] or ''}")


def main() -> None:
    configured = os.getenv("AUDIT_LOG_FILE", "").strip()
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(configured) if configured else Path(temporary) / "audit.jsonl"
        audit = AuditLogger(path)
        audit.ensure_writable()
        start = len(path.read_text(encoding="utf-8").splitlines())
        demo_remote_access(audit)
        demo_site_to_site(audit)
        print_comparison()
        print_audit(path, start)


if __name__ == "__main__":
    main()
