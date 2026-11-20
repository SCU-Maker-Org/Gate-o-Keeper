"""Hardware boundaries. An unlock command ID identifies exactly one attempt."""

import hashlib
import re
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from hmac import compare_digest
from typing import Protocol

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC


class RelayResult(StrEnum):
    CONFIRMED = "confirmed"
    SIMULATED = "simulated"


class DoorRelay(ABC):
    @abstractmethod
    def unlock(self, door: str, command_id: str) -> RelayResult:
        """Return CONFIRMED only after device acknowledgement. Bound the wait."""


class SimulatedRelay(DoorRelay):
    def unlock(self, door: str, command_id: str) -> RelayResult:
        return RelayResult.SIMULATED


class InvalidScan(ValueError):
    pass


@dataclass(frozen=True)
class Scan:
    tag: str
    counter: int


class ScanVerifier(Protocol):
    @property
    def binding(self) -> str:
        """Stable configuration fingerprint, changed when outstanding proofs must expire."""
        ...

    def verify(self, params: Mapping[str, str]) -> Scan: ...


def _mac(key: bytes, data: bytes) -> bytes:
    cmac = CMAC(algorithms.AES(key))
    cmac.update(data)
    return cmac.finalize()


@dataclass(frozen=True)
class Ntag424:
    uid: bytes
    meta_key: bytes = field(repr=False)
    file_key: bytes = field(repr=False)

    @property
    def binding(self) -> str:
        return hashlib.sha256(self.uid + self.meta_key + self.file_key).hexdigest()

    def verify(self, params: Mapping[str, str]) -> Scan:
        encrypted, mac = params.get("e", ""), params.get("c", "")
        if not re.fullmatch(r"[a-fA-F0-9]{32}", encrypted) or not re.fullmatch(
            r"[a-fA-F0-9]{16}", mac
        ):
            raise InvalidScan
        cipher = Cipher(algorithms.AES(self.meta_key), modes.CBC(bytes(16))).decryptor()
        payload = cipher.update(bytes.fromhex(encrypted)) + cipher.finalize()
        uid, counter = payload[1:8], payload[8:11]
        key = _mac(self.file_key, bytes.fromhex("3CC300010080") + uid + counter)
        expected = _mac(key, b"")[1::2]
        if (
            not compare_digest(expected, bytes.fromhex(mac))
            or payload[0] != 0xC7
            or uid != self.uid
        ):
            raise InvalidScan
        return Scan(uid.hex(), int.from_bytes(counter, "little"))
