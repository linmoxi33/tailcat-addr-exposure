"""Minimal, strict CBOR reader/writer for tailcat address payloads.

Only the subset used by tailcat's ``wireConnInfo`` is supported:
definite-length maps, arrays, byte strings, text strings, unsigned and
negative integers, booleans and null.  Indefinite lengths and tags are
rejected on purpose: tailcat never emits them, and accepting them in a
security scanner would silently widen the format.
"""

from __future__ import annotations


class CBORError(ValueError):
    """Raised when a byte string is not valid canonical-enough CBOR."""


class Map(dict):
    """A CBOR map that remembers duplicate keys (rejected by the parser)."""


def _read_uint(data: bytes, pos: int, info: int):
    if info < 24:
        return info, pos
    if info == 24:
        if pos + 1 > len(data):
            raise CBORError("truncated uint8 argument")
        return data[pos], pos + 1
    if info == 25:
        if pos + 2 > len(data):
            raise CBORError("truncated uint16 argument")
        return int.from_bytes(data[pos:pos + 2], "big"), pos + 2
    if info == 26:
        if pos + 4 > len(data):
            raise CBORError("truncated uint32 argument")
        return int.from_bytes(data[pos:pos + 4], "big"), pos + 4
    if info == 27:
        if pos + 8 > len(data):
            raise CBORError("truncated uint64 argument")
        return int.from_bytes(data[pos:pos + 8], "big"), pos + 8
    if info == 31:
        raise CBORError("indefinite-length items are not valid in a tailcat address")
    raise CBORError("reserved additional-info value %d" % info)


def loads(data: bytes):
    value, pos = _loads(data, 0, 0)
    if pos != len(data):
        raise CBORError("trailing bytes after CBOR item (%d left)" % (len(data) - pos))
    return value


def _loads(data: bytes, pos: int, depth: int):
    if depth > 32:
        raise CBORError("CBOR nesting too deep")
    if pos >= len(data):
        raise CBORError("unexpected end of CBOR input")
    initial = data[pos]
    pos += 1
    major = initial >> 5
    info = initial & 0x1F

    if major == 0:
        return _read_uint(data, pos, info)
    if major == 1:
        n, pos = _read_uint(data, pos, info)
        return -1 - n, pos
    if major in (2, 3):
        n, pos = _read_uint(data, pos, info)
        if pos + n > len(data):
            raise CBORError("truncated %s string" % ("byte" if major == 2 else "text"))
        raw = data[pos:pos + n]
        pos += n
        if major == 2:
            return raw, pos
        try:
            return raw.decode("utf-8"), pos
        except UnicodeDecodeError as exc:
            raise CBORError("text string is not UTF-8: %s" % exc) from None
    if major == 4:
        n, pos = _read_uint(data, pos, info)
        out = []
        for _ in range(n):
            item, pos = _loads(data, pos, depth + 1)
            out.append(item)
        return out, pos
    if major == 5:
        n, pos = _read_uint(data, pos, info)
        out = Map()
        for _ in range(n):
            key, pos = _loads(data, pos, depth + 1)
            value, pos = _loads(data, pos, depth + 1)
            try:
                duplicate = key in out
            except TypeError:
                raise CBORError("unhashable CBOR map key") from None
            if duplicate:
                raise CBORError("duplicate CBOR map key %r" % (key,))
            out[key] = value
        return out, pos
    if major == 6:
        raise CBORError("CBOR tags are not valid in a tailcat address")
    # major 7: simple values
    if info == 20:
        return False, pos
    if info == 21:
        return True, pos
    if info == 22:
        return None, pos
    if info == 23:
        raise CBORError("undefined is not valid in a tailcat address")
    raise CBORError("unsupported CBOR simple value %d" % info)


def _encode_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def dumps(value) -> bytes:
    """Encode the subset needed to build fixtures and tests."""
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        if value >= 0:
            return _encode_head(0, value)
        return _encode_head(1, -1 - value)
    if isinstance(value, bytes):
        return _encode_head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _encode_head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _encode_head(4, len(value)) + b"".join(dumps(v) for v in value)
    if isinstance(value, dict):
        parts = [_encode_head(5, len(value))]
        for k, v in value.items():
            parts.append(dumps(k))
            parts.append(dumps(v))
        return b"".join(parts)
    raise TypeError("cannot CBOR-encode %r" % (type(value),))
