"""Pruebas de la simulación de VPN de acceso remoto y de VPN sitio a sitio."""

from __future__ import annotations

import json
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.comunicaciones_seguras.audit import AuditLogger
from src.comunicaciones_seguras.auth import AccessController, UserRecord, hash_password
from src.comunicaciones_seguras.vpn_sim import (
    SCENARIO_COMPARISON,
    RemoteAccessGateway,
    Site,
    SiteToSiteVPN,
    TunnelPacket,
    VPNAccessDenied,
    VPNServiceError,
)

PASSWORDS = {"admin": "clave-admin-1", "operador": "clave-oper-2", "consulta": "clave-cons-3"}
ROLES = {"admin": "administrador", "operador": "operador", "consulta": "consulta"}


def make_controller() -> AccessController:
    users = {}
    for name, password in PASSWORDS.items():
        salt = secrets.token_bytes(16)
        users[name] = UserRecord(name, ROLES[name], salt, hash_password(password, salt))
    return AccessController(users)


class FakeClock:
    """Reloj controlable para probar expiración y bloqueo sin esperar."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class VPNTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.audit_path = Path(self.directory.name) / "audit.jsonl"
        self.audit = AuditLogger(self.audit_path)

    def events(self) -> list[dict[str, object]]:
        if not self.audit_path.exists():
            return []
        return [json.loads(line) for line in self.audit_path.read_text(encoding="utf-8").splitlines()]

    def last_event(self) -> dict[str, object]:
        return self.events()[-1]


class RemoteAccessVPNTests(VPNTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.clock = FakeClock()
        self.gateway = RemoteAccessGateway(
            make_controller(), self.audit, session_ttl_seconds=60, max_failed_attempts=3,
            lockout_seconds=30, clock=self.clock,
        )

    def test_valid_user_authenticates_and_receives_virtual_ip(self) -> None:
        session = self.gateway.connect("consulta", PASSWORDS["consulta"], "203.0.113.10")
        self.assertEqual(session.role, "consulta")
        self.assertTrue(session.virtual_ip.startswith("10.30.0."))
        self.assertEqual(self.last_event()["operation"], "vpn_connect")
        self.assertEqual(self.last_event()["result"], "allowed")

    def test_invalid_credentials_are_rejected_and_audited_without_password(self) -> None:
        with self.assertRaises(VPNAccessDenied):
            self.gateway.connect("admin", "contraseña-incorrecta", "203.0.113.10")
        event = self.last_event()
        self.assertEqual((event["operation"], event["result"], event["reason"]), ("vpn_connect", "denied", "credenciales_invalidas"))
        self.assertNotIn("contraseña-incorrecta", self.audit_path.read_text(encoding="utf-8"))
        self.assertEqual(self.gateway.session_count(), 0)

    def test_unknown_user_gets_same_public_error_as_wrong_password(self) -> None:
        with self.assertRaises(VPNAccessDenied) as unknown:
            self.gateway.connect("fantasma", "x", "203.0.113.10")
        with self.assertRaises(VPNAccessDenied) as wrong:
            self.gateway.connect("admin", "x", "203.0.113.10")
        self.assertEqual(str(unknown.exception), str(wrong.exception))

    def test_connecting_does_not_grant_unlimited_access(self) -> None:
        """Autenticarse no equivale a poder entrar a todo: el rol limita los recursos."""
        session = self.gateway.connect("consulta", PASSWORDS["consulta"], "203.0.113.10")
        self.assertIn("intranet-web", self.gateway.access(session.session_id, "intranet-web"))
        for resource in ("servidor-archivos", "panel-administracion", "base-datos"):
            with self.subTest(resource=resource), self.assertRaises(VPNAccessDenied):
                self.gateway.access(session.session_id, resource)
        event = self.last_event()
        self.assertEqual((event["username"], event["result"], event["reason"]), ("consulta", "denied", "privilegios_insuficientes"))

    def test_access_depends_on_role(self) -> None:
        expected = {
            "consulta": ["intranet-web"],
            "operador": ["intranet-web", "servidor-archivos"],
            "admin": ["base-datos", "intranet-web", "panel-administracion", "servidor-archivos"],
        }
        for username, resources in expected.items():
            with self.subTest(username=username):
                session = self.gateway.connect(username, PASSWORDS[username], "203.0.113.10")
                self.assertEqual(self.gateway.resources_for(session.session_id), resources)
                for resource in resources:
                    self.gateway.access(session.session_id, resource)

    def test_each_session_gets_a_different_virtual_ip(self) -> None:
        first = self.gateway.connect("admin", PASSWORDS["admin"], "203.0.113.10")
        second = self.gateway.connect("operador", PASSWORDS["operador"], "203.0.113.11")
        self.assertNotEqual(first.virtual_ip, second.virtual_ip)
        self.assertNotEqual(first.session_id, second.session_id)

    def test_invalid_or_forged_session_is_rejected(self) -> None:
        for forged in ("no-existe", "", None, 123):
            with self.subTest(session=forged), self.assertRaises(VPNAccessDenied):
                self.gateway.access(forged, "intranet-web")
        self.assertEqual(self.last_event()["reason"], "sesion_invalida")

    def test_unknown_resource_is_rejected(self) -> None:
        session = self.gateway.connect("admin", PASSWORDS["admin"], "203.0.113.10")
        with self.assertRaises(VPNAccessDenied):
            self.gateway.access(session.session_id, "recurso-inventado")
        self.assertEqual(self.last_event()["reason"], "recurso_inexistente")

    def test_session_expires(self) -> None:
        session = self.gateway.connect("operador", PASSWORDS["operador"], "203.0.113.10")
        self.gateway.access(session.session_id, "servidor-archivos")
        self.clock.now += 61
        with self.assertRaises(VPNAccessDenied):
            self.gateway.access(session.session_id, "servidor-archivos")
        self.assertEqual(self.last_event()["reason"], "sesion_expirada")

    def test_disconnect_revokes_the_session(self) -> None:
        session = self.gateway.connect("admin", PASSWORDS["admin"], "203.0.113.10")
        self.gateway.disconnect(session.session_id)
        with self.assertRaises(VPNAccessDenied):
            self.gateway.access(session.session_id, "base-datos")
        with self.assertRaises(VPNAccessDenied):
            self.gateway.disconnect(session.session_id)

    def test_account_is_locked_after_repeated_failures_even_with_correct_password(self) -> None:
        for _ in range(3):
            with self.assertRaises(VPNAccessDenied):
                self.gateway.connect("admin", "mala", "203.0.113.10")
        with self.assertRaises(VPNAccessDenied):
            self.gateway.connect("admin", PASSWORDS["admin"], "203.0.113.10")
        self.assertEqual(self.last_event()["reason"], "cuenta_bloqueada_temporalmente")
        self.clock.now += 31
        self.assertTrue(self.gateway.connect("admin", PASSWORDS["admin"], "203.0.113.10").session_id)

    def test_invalid_client_address_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.gateway.connect("admin", PASSWORDS["admin"], "no-es-una-ip")

    def test_gateway_fails_closed_when_audit_is_unavailable(self) -> None:
        blocked = Path(self.directory.name) / "bloqueado"
        blocked.mkdir()
        gateway = RemoteAccessGateway(make_controller(), AuditLogger(blocked), clock=self.clock)
        with self.assertRaises(VPNServiceError):
            gateway.connect("admin", PASSWORDS["admin"], "203.0.113.10")
        self.assertEqual(gateway.session_count(), 0)

    def test_audit_log_records_connection_access_and_disconnection(self) -> None:
        session = self.gateway.connect("operador", PASSWORDS["operador"], "203.0.113.10")
        self.gateway.access(session.session_id, "servidor-archivos")
        with self.assertRaises(VPNAccessDenied):
            self.gateway.access(session.session_id, "panel-administracion")
        self.gateway.disconnect(session.session_id)
        summary = [(e["operation"], e["result"]) for e in self.events()]
        self.assertEqual(summary, [
            ("vpn_connect", "allowed"),
            ("vpn_access:servidor-archivos", "allowed"),
            ("vpn_access:panel-administracion", "denied"),
            ("vpn_disconnect", "allowed"),
        ])
        self.assertNotIn(session.session_id, self.audit_path.read_text(encoding="utf-8"))


class SiteToSiteVPNTests(VPNTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.vpn = SiteToSiteVPN(
            Site("Oficina central", "10.10.0.0/24"), Site("Sucursal", "10.20.0.0/24"),
            secrets.token_bytes(32), self.audit,
        )

    def test_traffic_flows_in_both_directions(self) -> None:
        outgoing = self.vpn.send("10.10.0.5", "10.20.0.7", "consulta de inventario")
        self.assertEqual(outgoing.direction, "A->B")
        self.assertEqual(self.vpn.receive(outgoing), {
            "source": "10.10.0.5", "destination": "10.20.0.7", "data": "consulta de inventario",
        })
        reply = self.vpn.send("10.20.0.7", "10.10.0.5", "respuesta")
        self.assertEqual(reply.direction, "B->A")
        self.assertEqual(self.vpn.receive(reply)["data"], "respuesta")

    def test_packets_use_tunnel_mode_with_outer_and_inner_headers(self) -> None:
        packet = json.loads(self.vpn.send("10.10.0.5", "10.20.0.7", "x").wire)
        self.assertEqual(packet["mode"], "tunnel")
        self.assertIn("outer", packet)
        self.assertIn("inner", packet)
        self.assertNotIn("payload_b64", packet)

    def test_replayed_packet_is_rejected_and_audited(self) -> None:
        packet = self.vpn.send("10.10.0.5", "10.20.0.7", "transferencia única")
        self.vpn.receive(packet)
        with self.assertRaises(VPNAccessDenied):
            self.vpn.receive(packet)
        event = self.last_event()
        self.assertEqual((event["operation"], event["result"], event["reason"]), (
            "vpn_s2s_receive:A->B", "denied", "ipsec_replay_duplicate"))

    def test_tampered_packet_is_rejected(self) -> None:
        packet = self.vpn.send("10.10.0.5", "10.20.0.7", "original")
        document = json.loads(packet.wire)
        document["inner"]["payload_b64"] = "bWFsaWNpb3Nv"  # "malicioso"
        forged = TunnelPacket(packet.direction, json.dumps(document))
        with self.assertRaises(VPNAccessDenied):
            self.vpn.receive(forged)
        self.assertEqual(self.last_event()["reason"], "ipsec_integrity_failed")

    def test_gateway_with_wrong_key_cannot_inject_packets(self) -> None:
        attacker = SiteToSiteVPN(
            Site("Oficina central", "10.10.0.0/24"), Site("Sucursal", "10.20.0.0/24"),
            secrets.token_bytes(32), self.audit,
        )
        forged = attacker.send("10.10.0.5", "10.20.0.7", "inyectado")
        with self.assertRaises(VPNAccessDenied):
            self.vpn.receive(forged)
        self.assertEqual(self.last_event()["reason"], "ipsec_integrity_failed")

    def test_packet_cannot_be_redirected_to_the_opposite_direction(self) -> None:
        packet = self.vpn.send("10.10.0.5", "10.20.0.7", "x")
        with self.assertRaises(VPNAccessDenied):
            self.vpn.receive(TunnelPacket("B->A", packet.wire))

    def test_traffic_outside_the_policy_is_rejected(self) -> None:
        cases = (
            ("10.10.0.5", "8.8.8.8"),        # destino que no es la otra red
            ("192.168.1.9", "10.20.0.7"),    # origen que no pertenece a ningún sitio
            ("10.10.0.5", "10.10.0.6"),      # tráfico local: no necesita el túnel
        )
        for source, destination in cases:
            with self.subTest(source=source, destination=destination), self.assertRaises(VPNAccessDenied):
                self.vpn.send(source, destination, "x")
        self.assertEqual(self.last_event()["reason"], "trafico_fuera_de_politica")

    def test_invalid_addresses_are_rejected(self) -> None:
        with self.assertRaises(VPNAccessDenied):
            self.vpn.send("no-ip", "10.20.0.7", "x")

    def test_overlapping_subnets_and_weak_key_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            SiteToSiteVPN(Site("A", "10.10.0.0/24"), Site("B", "10.10.0.0/25"), secrets.token_bytes(32), self.audit)
        with self.assertRaises(ValueError):
            SiteToSiteVPN(Site("A", "10.10.0.0/24"), Site("B", "10.20.0.0/24"), b"corta", self.audit)

    def test_site_to_site_has_no_user_authentication(self) -> None:
        """Cualquier equipo de la subred permitida usa el túnel sin iniciar sesión."""
        packet = self.vpn.send("10.10.0.99", "10.20.0.1", "sin usuario")
        self.vpn.receive(packet)
        self.assertTrue(all(event["username"] is None for event in self.events()))

    def test_scenarios_are_clearly_different(self) -> None:
        rows = {aspect: (remote, site) for aspect, remote, site in SCENARIO_COMPARISON}
        self.assertNotEqual(*rows["Autenticación"])
        self.assertNotEqual(*rows["Autorización"])
        self.assertNotEqual(*rows["Qué conecta"])


if __name__ == "__main__":
    unittest.main()
