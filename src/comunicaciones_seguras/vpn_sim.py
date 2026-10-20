"""Simulación educativa de VPN de acceso remoto y de VPN sitio a sitio.

No crea interfaces de red ni túneles del sistema operativo: representa, dentro de la
aplicación, lo que distingue a cada escenario.

* Acceso remoto: un USUARIO se autentica (identidad), recibe una IP virtual y, después de
  conectarse, solo alcanza los recursos que permite su rol (autorización).
* Sitio a sitio: dos GATEWAYS conectan dos redes. No hay usuarios; los equipos de cada red
  usan el túnel de forma transparente y la política depende de las subredes. Cada paquete se
  protege con la simulación IPSec en modo túnel (HMAC y ventana anti-replay).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable, Final

from .audit import AuditLogger
from .auth import AccessController, AuthenticationError
from .ipsec_sim import IPSecSimulationConfig, IPSecSimulationError, IPSecSimulator

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
MAX_TRACKED_NAMES: Final = 1024
MAX_NAME_LENGTH: Final = 64


class VPNError(Exception):
    """Base de los errores de la simulación VPN; reason es apto para auditoría."""

    reason = "vpn_error"


class VPNAccessDenied(VPNError):
    """Acceso rechazado. El motivo detallado solo se registra en la auditoría."""

    def __init__(self, reason: str) -> None:
        super().__init__("Acceso denegado.")
        self.reason = reason


class VPNServiceError(VPNError):
    """El servicio no puede operar con seguridad (por ejemplo, sin auditoría disponible)."""

    reason = "auditoria_no_disponible"


# --------------------------------------------------------------------------------------
# VPN de acceso remoto
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class InternalResource:
    """Recurso de la red privada y los roles autorizados a usarlo a través de la VPN."""

    name: str
    address: str
    allowed_roles: frozenset[str]
    description: str


DEFAULT_RESOURCES: Final = (
    InternalResource(
        "intranet-web", "10.10.0.10",
        frozenset({"consulta", "operador", "administrador"}), "Portal interno de consulta",
    ),
    InternalResource(
        "servidor-archivos", "10.10.0.20",
        frozenset({"operador", "administrador"}), "Archivos compartidos de operación",
    ),
    InternalResource(
        "panel-administracion", "10.10.0.30",
        frozenset({"administrador"}), "Consola de administración de equipos",
    ),
    InternalResource(
        "base-datos", "10.10.0.40",
        frozenset({"administrador"}), "Servidor de base de datos interno",
    ),
)


@dataclass(frozen=True)
class VPNSession:
    """Sesión de acceso remoto concedida tras autenticar al usuario."""

    session_id: str
    username: str
    role: str
    virtual_ip: str
    client_address: str
    expires_at: float


class RemoteAccessGateway:
    """Gateway de acceso remoto: autentica al usuario y limita lo que puede alcanzar."""

    def __init__(
        self,
        controller: AccessController,
        audit_logger: AuditLogger,
        *,
        resources: tuple[InternalResource, ...] = DEFAULT_RESOURCES,
        address_pool: str = "10.30.0.0/24",
        session_ttl_seconds: int = 900,
        max_failed_attempts: int = 3,
        lockout_seconds: int = 60,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 1 <= session_ttl_seconds <= 86400:
            raise ValueError("La vigencia de sesión está fuera de rango.")
        if not 1 <= max_failed_attempts <= 10 or not 1 <= lockout_seconds <= 3600:
            raise ValueError("La política de bloqueo está fuera de rango.")
        if not resources:
            raise ValueError("Debe existir al menos un recurso interno.")
        self._controller = controller
        self._audit = audit_logger
        self._resources = {resource.name: resource for resource in resources}
        self._network = ipaddress.ip_network(address_pool, strict=True)
        self._ttl = session_ttl_seconds
        self._max_failed = max_failed_attempts
        self._lockout = lockout_seconds
        self._clock = clock
        self._sessions: dict[str, VPNSession] = {}
        self._failures: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    # -- auditoría ---------------------------------------------------------------------

    def _record(self, username: str | None, operation: str, result: str, reason: str | None) -> None:
        try:
            self._audit.record(username=username, operation=operation, result=result, reason=reason)
        except OSError as error:
            raise VPNServiceError("No se pudo registrar el evento de auditoría.") from error

    # -- bloqueo por intentos fallidos --------------------------------------------------

    def _is_locked(self, name: str, now: float) -> bool:
        count, locked_until = self._failures.get(name, (0, 0.0))
        return count >= self._max_failed and now < locked_until

    def _register_failure(self, name: str | None, now: float) -> None:
        # El bloqueo se aplica igual a usuarios existentes e inexistentes para no revelar cuentas.
        if name is None or len(name) > MAX_NAME_LENGTH:
            return
        if len(self._failures) >= MAX_TRACKED_NAMES:
            self._failures = {key: value for key, value in self._failures.items() if value[1] > now}
            if len(self._failures) >= MAX_TRACKED_NAMES:
                return
        count, locked_until = self._failures.get(name, (0, 0.0))
        if now >= locked_until:
            count = 0  # la ventana de conteo anterior terminó; se empieza de nuevo
        count += 1
        self._failures[name] = (count, now + self._lockout)

    # -- sesiones -----------------------------------------------------------------------

    def _purge_expired(self, now: float) -> None:
        expired = [key for key, session in self._sessions.items() if session.expires_at <= now]
        for key in expired:
            del self._sessions[key]

    def _allocate_ip(self) -> str:
        used = {session.virtual_ip for session in self._sessions.values()}
        hosts = self._network.hosts()
        next(hosts, None)  # la primera dirección queda reservada para el gateway
        for host in hosts:
            if str(host) not in used:
                return str(host)
        raise VPNAccessDenied("pool_direcciones_agotado")

    def session_count(self) -> int:
        with self._lock:
            self._purge_expired(self._clock())
            return len(self._sessions)

    # -- operaciones --------------------------------------------------------------------

    def connect(self, username: object, password: object, client_address: str) -> VPNSession:
        """AUTENTICACIÓN: verifica la identidad y entrega una IP virtual. No otorga recursos."""
        try:
            ipaddress.ip_address(client_address)
        except ValueError as error:
            raise ValueError("La dirección del cliente no es válida.") from error
        now = self._clock()
        name = username if isinstance(username, str) else None
        with self._lock:
            locked = name is not None and self._is_locked(name, now)
        if locked:
            self._record(name, "vpn_connect", "denied", "cuenta_bloqueada_temporalmente")
            raise VPNAccessDenied("cuenta_bloqueada_temporalmente")
        try:
            user = self._controller.authenticate(username, password)
        except AuthenticationError:
            with self._lock:
                self._register_failure(name, now)
            self._record(name, "vpn_connect", "denied", "credenciales_invalidas")
            raise VPNAccessDenied("credenciales_invalidas") from None
        with self._lock:
            self._failures.pop(user.username, None)
            self._purge_expired(now)
            try:
                virtual_ip = self._allocate_ip()
            except VPNAccessDenied as error:
                exhausted = error
            else:
                exhausted = None
                session = VPNSession(
                    secrets.token_urlsafe(32), user.username, user.role, virtual_ip,
                    client_address, now + self._ttl,
                )
                self._sessions[session.session_id] = session
        if exhausted is not None:
            self._record(user.username, "vpn_connect", "denied", exhausted.reason)
            raise exhausted
        try:
            self._record(user.username, "vpn_connect", "allowed", None)
        except VPNServiceError:
            with self._lock:
                self._sessions.pop(session.session_id, None)
            raise
        return session

    def resources_for(self, session_id: str) -> list[str]:
        """Lista los recursos que el rol de la sesión puede alcanzar (sin registrar eventos)."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.expires_at <= self._clock():
                return []
            return sorted(name for name, res in self._resources.items() if session.role in res.allowed_roles)

    def access(self, session_id: object, resource_name: object) -> str:
        """AUTORIZACIÓN: con la sesión ya creada, decide si el rol puede usar el recurso."""
        now = self._clock()
        expired_user: str | None = None
        with self._lock:
            session = self._sessions.get(session_id) if isinstance(session_id, str) else None
            if session is not None and session.expires_at <= now:
                expired_user = session.username
                del self._sessions[session.session_id]
                session = None
        resource = self._resources.get(resource_name) if isinstance(resource_name, str) else None
        operation = f"vpn_access:{resource.name}" if resource else "vpn_access:<desconocido>"
        if session is None:
            reason = "sesion_expirada" if expired_user else "sesion_invalida"
            self._record(expired_user, operation, "denied", reason)
            raise VPNAccessDenied(reason)
        if resource is None:
            self._record(session.username, operation, "denied", "recurso_inexistente")
            raise VPNAccessDenied("recurso_inexistente")
        if session.role not in resource.allowed_roles:
            self._record(session.username, operation, "denied", "privilegios_insuficientes")
            raise VPNAccessDenied("privilegios_insuficientes")
        self._record(session.username, operation, "allowed", None)
        return f"Acceso concedido a {resource.name} ({resource.address})."

    def disconnect(self, session_id: object) -> None:
        with self._lock:
            session = self._sessions.pop(session_id, None) if isinstance(session_id, str) else None
        if session is None:
            self._record(None, "vpn_disconnect", "denied", "sesion_invalida")
            raise VPNAccessDenied("sesion_invalida")
        self._record(session.username, "vpn_disconnect", "allowed", None)


# --------------------------------------------------------------------------------------
# VPN sitio a sitio
# --------------------------------------------------------------------------------------

DIRECTIONS: Final = ("A->B", "B->A")


@dataclass(frozen=True)
class Site:
    """Red privada detrás de un gateway."""

    name: str
    subnet: str


@dataclass(frozen=True)
class TunnelPacket:
    """Paquete que viaja entre gateways por la red no confiable."""

    direction: str
    wire: str


class SiteToSiteVPN:
    """Túnel entre dos gateways. No autentica usuarios: protege tráfico entre dos redes."""

    def __init__(
        self,
        site_a: Site,
        site_b: Site,
        pre_shared_key: bytes,
        audit_logger: AuditLogger,
        *,
        replay_window: int = 64,
    ) -> None:
        if not isinstance(pre_shared_key, bytes) or len(pre_shared_key) < 32:
            raise ValueError("La clave precompartida debe tener al menos 32 bytes.")
        self._networks = {
            "A": ipaddress.ip_network(site_a.subnet, strict=True),
            "B": ipaddress.ip_network(site_b.subnet, strict=True),
        }
        if self._networks["A"].overlaps(self._networks["B"]):
            raise ValueError("Las subredes de los dos sitios no pueden solaparse.")
        self._sites = {"A": site_a, "B": site_b}
        self._audit = audit_logger
        # Cada dirección tiene su propia asociación (clave y SPI). El emisor vive en el gateway de
        # entrada y el receptor, con su propia ventana anti-replay, en el gateway de salida.
        self._senders: dict[str, IPSecSimulator] = {}
        self._receivers: dict[str, IPSecSimulator] = {}
        for direction, spi in (("A->B", "S2S-A2B"), ("B->A", "S2S-B2A")):
            key = hmac.new(pre_shared_key, f"s2s-key:{direction}".encode(), hashlib.sha256).digest()
            config = IPSecSimulationConfig(key, spi, "tunnel", replay_window)
            self._senders[direction] = IPSecSimulator(config)
            self._receivers[direction] = IPSecSimulator(config)

    def _record(self, operation: str, result: str, reason: str | None) -> None:
        try:
            self._audit.record(username=None, operation=operation, result=result, reason=reason)
        except OSError as error:
            raise VPNServiceError("No se pudo registrar el evento de auditoría.") from error

    def _direction_for(self, source: IPAddress, destination: IPAddress) -> str | None:
        """Solo se permite tráfico de una red a la otra; todo lo demás queda fuera de la política."""
        if source in self._networks["A"] and destination in self._networks["B"]:
            return "A->B"
        if source in self._networks["B"] and destination in self._networks["A"]:
            return "B->A"
        return None

    def send(self, source_ip: str, destination_ip: str, data: str) -> TunnelPacket:
        """Gateway de entrada: valida la política y encapsula el paquete en modo túnel."""
        try:
            source = ipaddress.ip_address(source_ip)
            destination = ipaddress.ip_address(destination_ip)
        except ValueError:
            self._record("vpn_s2s_send", "denied", "direccion_invalida")
            raise VPNAccessDenied("direccion_invalida") from None
        direction = self._direction_for(source, destination)
        if direction is None:
            self._record("vpn_s2s_send", "denied", "trafico_fuera_de_politica")
            raise VPNAccessDenied("trafico_fuera_de_politica")
        inner = json.dumps({"src": str(source), "dst": str(destination), "data": data}, ensure_ascii=True)
        wire = self._senders[direction].encapsulate(inner)
        self._record(f"vpn_s2s_send:{direction}", "allowed", None)
        return TunnelPacket(direction, wire)

    def receive(self, packet: TunnelPacket) -> dict[str, str]:
        """Gateway de salida: verifica HMAC, rechaza repetidos y aplica de nuevo la política."""
        if not isinstance(packet, TunnelPacket) or packet.direction not in self._receivers:
            self._record("vpn_s2s_receive", "denied", "paquete_invalido")
            raise VPNAccessDenied("paquete_invalido")
        operation = f"vpn_s2s_receive:{packet.direction}"
        try:
            inner_text = self._receivers[packet.direction].decapsulate(packet.wire)
        except IPSecSimulationError as error:
            self._record(operation, "denied", error.reason)
            raise VPNAccessDenied(error.reason) from None
        try:
            inner = json.loads(inner_text)
            if set(inner) != {"src", "dst", "data"} or not isinstance(inner["data"], str):
                raise ValueError("campos inesperados")
            source = ipaddress.ip_address(inner["src"])
            destination = ipaddress.ip_address(inner["dst"])
        except (TypeError, ValueError):
            self._record(operation, "denied", "carga_interna_invalida")
            raise VPNAccessDenied("carga_interna_invalida") from None
        if self._direction_for(source, destination) != packet.direction:
            self._record(operation, "denied", "trafico_fuera_de_politica")
            raise VPNAccessDenied("trafico_fuera_de_politica")
        self._record(operation, "allowed", None)
        return {"source": str(source), "destination": str(destination), "data": inner["data"]}


# --------------------------------------------------------------------------------------
# Comparación de escenarios (se usa en la demostración y en la documentación)
# --------------------------------------------------------------------------------------

SCENARIO_COMPARISON: Final = (
    ("Qué conecta", "Un usuario remoto con una red privada", "Dos redes completas entre sí"),
    ("Extremos del túnel", "Cliente VPN y gateway", "Gateway contra gateway"),
    ("Autenticación", "Usuario y contraseña de cada persona", "Clave precompartida entre gateways"),
    ("Autorización", "Por rol, después de conectar", "Por subredes de origen y destino"),
    ("Dirección interna", "IP virtual asignada a cada sesión", "Los equipos conservan su IP de LAN"),
    ("Quién usa el túnel", "Solo la persona autenticada", "Cualquier equipo permitido de ambas redes"),
    ("Protección de paquetes", "Sesión autenticada", "IPSec simulado en modo túnel con anti-replay"),
)
