"""Simulación educativa de encapsulado tipo IPSec; no implementa IPSec real."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import threading
from dataclasses import dataclass
from typing import Final

VERSION: Final = 1
AUTH_TAG_BYTES: Final = 32
VALID_MODES: Final = frozenset({"transport", "tunnel"})


class IPSecSimulationError(Exception):
    """Base para rechazos seguros; reason es apto para auditoría sin secretos."""

    reason = "ipsec_invalid_packet"


class PacketFormatError(IPSecSimulationError):
    reason = "ipsec_invalid_packet"


class IntegrityError(IPSecSimulationError):
    reason = "ipsec_integrity_failed"


class ReplayError(IPSecSimulationError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PacketFormatError("Campo JSON duplicado.")
        result[key] = value
    return result


def _canonical_bytes(fields: dict[str, object]) -> bytes:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _encode_tag(key: bytes, fields: dict[str, object]) -> str:
    return base64.b64encode(hmac.new(key, _canonical_bytes(fields), hashlib.sha256).digest()).decode("ascii")


def _decode_base64(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise PacketFormatError(f"{field} debe ser texto base64.")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as error:
        raise PacketFormatError(f"{field} no es base64 válido.") from error


@dataclass(frozen=True)
class IPSecSimulationConfig:
    key: bytes
    spi: str
    mode: str
    replay_window: int = 64
    max_message_bytes: int = 2048
    sequence_start: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.key, bytes):
            raise ValueError("La clave de simulación debe ser bytes.")
        if len(self.key) != 32:
            raise ValueError("La clave de simulación debe tener 32 bytes.")
        if not self.spi or len(self.spi) > 64 or not all(character.isalnum() or character in "_-" for character in self.spi):
            raise ValueError("SPI inválido.")
        if self.mode not in VALID_MODES:
            raise ValueError("Modo de simulación inválido.")
        if not 1 <= self.replay_window <= 1024:
            raise ValueError("Ventana anti-replay fuera de rango.")
        if not 1 <= self.max_message_bytes <= 2048:
            raise ValueError("Tamaño máximo de mensaje fuera de rango.")
        if not 1 <= self.sequence_start <= 2**63 - 1:
            raise ValueError("Secuencia inicial inválida.")


class ReplayWindow:
    """Ventana deslizante con lock; solo se modifica tras validar el HMAC."""

    def __init__(self, size: int) -> None:
        self._size = size
        self._highest = 0
        self._bitmap = 0
        self._mask = (1 << size) - 1
        self._lock = threading.Lock()

    def accept(self, sequence: int) -> None:
        with self._lock:
            if sequence > self._highest:
                distance = sequence - self._highest
                self._bitmap = 1 if distance >= self._size else ((self._bitmap << distance) | 1) & self._mask
                self._highest = sequence
                return
            distance = self._highest - sequence
            if distance >= self._size:
                raise ReplayError("ipsec_replay_stale")
            bit = 1 << distance
            if self._bitmap & bit:
                raise ReplayError("ipsec_replay_duplicate")
            self._bitmap |= bit


class IPSecSimulator:
    """Encapsula y desencapsula mensajes en una asociación simulada única."""

    def __init__(self, config: IPSecSimulationConfig) -> None:
        self._config = config
        self._next_sequence = config.sequence_start
        self._sender_lock = threading.Lock()
        self._replay = ReplayWindow(config.replay_window)

    def encapsulate(self, message: str) -> str:
        if not isinstance(message, str):
            raise PacketFormatError("El mensaje debe ser texto UTF-8.")
        payload = message.encode("utf-8")
        if len(payload) > self._config.max_message_bytes:
            raise PacketFormatError("Mensaje demasiado grande.")
        with self._sender_lock:
            sequence = self._next_sequence
            self._next_sequence += 1
        fields: dict[str, object] = {
            "version": VERSION,
            "mode": self._config.mode,
            "spi": self._config.spi,
            "sequence": sequence,
        }
        encoded_payload = base64.b64encode(payload).decode("ascii")
        if self._config.mode == "transport":
            fields["payload_b64"] = encoded_payload
        else:
            fields["outer"] = {"source": "sim-client", "destination": "sim-gateway"}
            fields["inner"] = {
                "source": "client", "destination": "server", "payload_b64": encoded_payload,
            }
        packet = {**fields, "auth_tag": _encode_tag(self._config.key, fields)}
        return _canonical_bytes(packet).decode("utf-8")

    def decapsulate(self, envelope: str) -> str:
        if not isinstance(envelope, str) or len(envelope.encode("utf-8")) > self._config.max_message_bytes * 3:
            raise PacketFormatError("Sobre de simulación inválido o demasiado grande.")
        try:
            packet = json.loads(envelope, object_pairs_hook=_reject_duplicates)
        except (json.JSONDecodeError, PacketFormatError) as error:
            raise PacketFormatError("JSON de simulación inválido.") from error
        if not isinstance(packet, dict):
            raise PacketFormatError("El sobre debe ser un objeto JSON.")
        expected_fields = {"version", "mode", "spi", "sequence", "auth_tag", "payload_b64"}
        if packet.get("mode") == "tunnel":
            expected_fields = {"version", "mode", "spi", "sequence", "auth_tag", "outer", "inner"}
        if set(packet) != expected_fields:
            raise PacketFormatError("Campos de sobre inválidos.")
        version, mode, spi, sequence = packet["version"], packet["mode"], packet["spi"], packet["sequence"]
        if type(version) is not int or version != VERSION or mode != self._config.mode or spi != self._config.spi:
            raise PacketFormatError("Versión, modo o SPI inválidos.")
        if type(sequence) is not int or not 1 <= sequence <= 2**63 - 1:
            raise PacketFormatError("Secuencia inválida.")
        protected = {key: value for key, value in packet.items() if key != "auth_tag"}
        tag = _decode_base64(packet["auth_tag"], "auth_tag")
        if len(tag) != AUTH_TAG_BYTES or not hmac.compare_digest(tag, hmac.new(self._config.key, _canonical_bytes(protected), hashlib.sha256).digest()):
            raise IntegrityError("Etiqueta HMAC inválida.")
        if mode == "transport":
            payload = _decode_base64(packet["payload_b64"], "payload_b64")
        else:
            outer, inner = packet["outer"], packet["inner"]
            if not isinstance(outer, dict) or not isinstance(inner, dict):
                raise PacketFormatError("Encabezados de túnel inválidos.")
            if set(outer) != {"source", "destination"} or set(inner) != {"source", "destination", "payload_b64"}:
                raise PacketFormatError("Campos de túnel inválidos.")
            if not all(isinstance(value, str) and value for value in [*outer.values(), inner["source"], inner["destination"]]):
                raise PacketFormatError("Direcciones de túnel inválidas.")
            payload = _decode_base64(inner["payload_b64"], "inner.payload_b64")
        if len(payload) > self._config.max_message_bytes:
            raise PacketFormatError("Carga interna demasiado grande.")
        try:
            message = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise PacketFormatError("La carga interna no es UTF-8.") from error
        self._replay.accept(sequence)
        return message
