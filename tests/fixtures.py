"""Deterministic tailcat address builders for tests and examples.

These are synthesized from the documented wire layout (wire.go), not
harvested from a live server: no real secret appears in this repository.
"""

import base64
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tailcat_addr_exposure import cbor  # noqa: E402


def _key(seed: str, n: int = 32) -> bytes:
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(("%s:%d" % (seed, counter)).encode()).digest()
        counter += 1
    return out[:n]


def encode(payload) -> str:
    return "tc" + base64.urlsafe_b64encode(cbor.dumps(payload)).decode().rstrip("=")


def bearer(region_id=1, with_disco=True, tag="bearer"):
    payload = {"p": _key(tag + ":server"), "i": region_id}
    if with_disco:
        payload["k"] = _key(tag + ":disco")
    payload["q"] = _key(tag + ":psk")
    return encode(payload)


def no_psk(region_id=2, with_disco=True, tag="nopsk"):
    payload = {"p": _key(tag + ":server"), "i": region_id}
    if with_disco:
        payload["k"] = _key(tag + ":disco")
    return encode(payload)


def embedded_derp(tag="embedded"):
    payload = {
        "p": _key(tag + ":server"),
        "k": _key(tag + ":disco"),
        "r": [
            {
                "i": 900,
                "c": "test",
                "m": "Test Region",
                "N": [
                    {"n": "test1", "h": "derp1.example.net", "4": "203.0.113.10", "s": 3478},
                    {"n": "test2", "h": "derp2.example.net", "6": "2001:db8::10"},
                ],
            }
        ],
    }
    return encode(payload)


def embedded_bearer(tag="embedded-bearer"):
    payload = {
        "p": _key(tag + ":server"),
        "k": _key(tag + ":disco"),
        "q": _key(tag + ":psk"),
        "r": [
            {
                "i": 901,
                "c": "pub",
                "m": "Public Region",
                "N": [{"n": "pub1", "h": "derp.example.org", "4": "198.51.100.7"}],
            }
        ],
    }
    return encode(payload)


def no_derp(tag="noderp"):
    # ConnInfo.Addr() omits RegionID when it is the zero value.
    return encode({"p": _key(tag + ":server")})


def bad_key_length(tag="badkey"):
    return encode({"p": _key(tag + ":server")[:16], "i": 1})


def missing_server_key(tag="nokey"):
    return encode({"k": _key(tag + ":disco"), "i": 1})


def unknown_field(tag="unknown"):
    return encode({"p": _key(tag + ":server"), "i": 1, "z": "future"})


def trailing_bytes(tag="trailing"):
    raw = cbor.dumps({"p": _key(tag + ":server"), "i": 1}) + b"\x00\x01"
    return "tc" + base64.urlsafe_b64encode(raw).decode().rstrip("=")
