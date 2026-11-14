"""Offline parser for tailcat addresses (``tc`` + base64url(CBOR)).

The wire format is defined by tailscale/tailcat's ``wireConnInfo`` in
``wire.go``:

    p  server WireGuard public key       (32 bytes, required)
    k  server path-discovery public key  (32 bytes, optional)
    q  WireGuard pre-shared key          (32 bytes, optional, SECRET)
    r  full DERP region metadata         (array, optional)
    i  DERP region id                    (integer, optional)

This module never returns key material: the pre-shared key is only ever
observed as a boolean/length so that a report can be shared safely.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass, field

from . import cbor

PREFIX = "tc"
KEY_LEN = 32
KNOWN_FIELDS = {"p", "k", "q", "r", "i"}


class AddrError(ValueError):
    def __init__(self, rule: str, message: str, severity: str = "warning"):
        super().__init__(message)
        self.rule = rule
        self.message = message
        self.severity = severity


@dataclass
class ParsedAddress:
    text: str
    fingerprint: str
    length: int
    server_key: bytes = b""
    has_disco: bool = False
    has_psk: bool = False
    zero_psk: bool = False
    region_id: int | None = None
    regions: list = field(default_factory=list)
    unknown_fields: list = field(default_factory=list)
    no_derp: bool = False

    @property
    def masked(self) -> str:
        return "tc<redacted:%d chars:%s>" % (self.length, self.fingerprint[:12])

    def as_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "length": self.length,
            "masked": self.masked,
            "server_key_prefix": self.server_key[:8].hex() if self.server_key else None,
            "has_disco_key": self.has_disco,
            "has_psk": self.has_psk,
            "zero_psk_field": self.zero_psk,
            "region_id": self.region_id,
            "embedded_derp_regions": [r.get("region_code") or r.get("region_id") for r in self.regions],
            "unknown_fields": sorted(self.unknown_fields),
            "has_derp_info": not self.no_derp,
        }


ADDR_RE = re.compile(r"(?<![A-Za-z0-9_\-])tc[A-Za-z0-9_\-]{40,}")


def looks_like_address(token: str) -> bool:
    return bool(token.startswith(PREFIX)) and len(token) > 40


def _b64decode(rest: str) -> bytes:
    if "=" in rest:
        raise AddrError("ADDR_PADDED_BASE64", "address uses '=' padding; tailcat uses raw base64url")
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", rest):
        raise AddrError("ADDR_INVALID_BASE64", "address body contains characters outside base64url")
    try:
        return base64.urlsafe_b64decode(rest + "=" * (-len(rest) % 4))
    except (binascii.Error, ValueError) as exc:
        raise AddrError("ADDR_INVALID_BASE64", "base64url decode failed: %s" % exc) from None


def _region_summary(value) -> list:
    out = []
    if not isinstance(value, list):
        raise AddrError("ADDR_BAD_REGION", "field 'r' is not an array", "error")
    for idx, region in enumerate(value):
        if not isinstance(region, dict):
            raise AddrError("ADDR_BAD_REGION", "region %d is not a map" % idx, "error")
        nodes = region.get("N") or []
        if not isinstance(nodes, list):
            raise AddrError("ADDR_BAD_REGION", "region %d nodes is not an array" % idx, "error")
        out.append(
            {
                "region_id": region.get("i"),
                "region_code": region.get("c"),
                "region_name": region.get("m"),
                "node_count": len(nodes),
            }
        )
    return out


def parse_address(text: str) -> ParsedAddress:
    """Parse one ``tc...`` string. Raises AddrError on malformed input."""
    text = text.strip()
    if not text.startswith(PREFIX):
        raise AddrError("ADDR_MISSING_PREFIX", "address does not start with 'tc'", "error")
    body = text[len(PREFIX):]
    raw = _b64decode(body)
    try:
        payload = cbor.loads(raw)
    except cbor.CBORError as exc:
        message = str(exc)
        rule = "ADDR_TRAILING_BYTES" if "trailing bytes" in message else "ADDR_CBOR_INVALID"
        raise AddrError(rule, "CBOR: %s" % message) from None
    if not isinstance(payload, dict):
        raise AddrError("ADDR_CBOR_INVALID", "CBOR payload is not a map", "error")

    parsed = ParsedAddress(
        text=text,
        fingerprint=hashlib.sha256(text.encode("ascii", "replace")).hexdigest(),
        length=len(text),
        unknown_fields=[str(k) for k in payload if k not in KNOWN_FIELDS],
    )

    server = payload.get("p")
    if server is None:
        raise AddrError("ADDR_NO_SERVER_KEY", "required field 'p' (server public key) is missing", "error")
    if not isinstance(server, bytes):
        raise AddrError("ADDR_BAD_SERVER_KEY", "field 'p' is not a byte string", "error")
    if len(server) != KEY_LEN:
        raise AddrError(
            "ADDR_BAD_SERVER_KEY",
            "server public key is %d bytes, want %d" % (len(server), KEY_LEN),
            "error",
        )
    parsed.server_key = server

    disco = payload.get("k")
    if disco is not None:
        if not isinstance(disco, bytes) or len(disco) != KEY_LEN:
            got = len(disco) if isinstance(disco, bytes) else type(disco).__name__
            raise AddrError("ADDR_BAD_DISCO_KEY", "path-discovery key is %s, want %d bytes" % (got, KEY_LEN), "error")
        parsed.has_disco = True

    psk = payload.get("q")
    if psk is not None:
        if not isinstance(psk, bytes) or len(psk) != KEY_LEN:
            got = len(psk) if isinstance(psk, bytes) else type(psk).__name__
            raise AddrError("ADDR_BAD_PSK", "pre-shared key is %s, want %d bytes" % (got, KEY_LEN), "error")
        parsed.has_psk = True
        parsed.zero_psk = psk == b"\x00" * KEY_LEN

    region_id = payload.get("i")
    if region_id is not None:
        if isinstance(region_id, bool) or not isinstance(region_id, int):
            raise AddrError("ADDR_BAD_REGION_ID", "field 'i' is not an integer", "error")
        if region_id < -1:
            raise AddrError("ADDR_BAD_REGION_ID", "field 'i' is %d, want -1 or a non-negative region id" % region_id, "error")
        parsed.region_id = region_id

    if "r" in payload:
        parsed.regions = _region_summary(payload["r"])
        if not parsed.regions:
            raise AddrError("ADDR_BAD_REGION", "field 'r' is an empty array", "error")

    # Upstream encodes RegionID with `omitempty`, so a ConnInfo whose region id is
    # the zero value still serializes to a valid address without 'i' or 'r'.
    # That is decodable by tailcat.ParseAddr; report it, do not reject it.
    if parsed.region_id is None and not parsed.regions:
        parsed.no_derp = True
    return parsed
