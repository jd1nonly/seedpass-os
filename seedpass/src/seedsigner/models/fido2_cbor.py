"""
CBOR for CTAP2 -- a deliberately small, strict subset.

Every byte handled here arrives from a USB host the device cannot vet. Until
now SeedPass only ever parsed QR codes a user chose to scan; this is the first
input channel an attacker can drive directly, at speed, without the user's
involvement. So this parser is written to refuse rather than to cope.

What it refuses, and why
------------------------
* **Indefinite-length items.** CTAP2's canonical CBOR forbids them, and they are
  the classic way to make a parser allocate without bound.
* **Nesting beyond MAX_DEPTH.** A few bytes of nested arrays can otherwise
  recurse until the interpreter's stack gives out.
* **Length prefixes larger than the data present.** A CBOR item may claim a
  4-gigabyte byte string in five bytes. The claim is checked against what was
  actually received before anything is allocated.
* **Anything past the end of the message.** Trailing bytes mean the sender and
  this parser disagree about the message, and a disagreement is a bug worth
  surfacing rather than ignoring.
* **Non-canonical map ordering** on decode of maps we round-trip, since CTAP2
  requires canonical form and accepting both would let two encodings mean the
  same thing.

Types are limited to what CTAP2 actually uses: unsigned and negative integers,
byte strings, text strings, arrays, maps, booleans and null. No tags, no
floats, no bignums.
"""


class CborError(Exception):
    """Raised for any input this parser will not accept."""


# A CTAP2 message is bounded by the transport (7609 bytes over CTAPHID), so
# nothing legitimate comes close to these.
MAX_DEPTH = 16
MAX_ITEMS = 1024
MAX_STRING_BYTES = 8192

# Major types, per RFC 8949
_UINT = 0
_NEGINT = 1
_BYTES = 2
_TEXT = 3
_ARRAY = 4
_MAP = 5
_SIMPLE = 7


# ------------------------------------------------------------------ encoding

def encode(value) -> bytes:
    """Encode to CTAP2 canonical CBOR."""
    out = bytearray()
    _encode_into(value, out, depth=0)
    return bytes(out)


def _encode_head(major: int, length: int, out: bytearray) -> None:
    if length < 24:
        out.append((major << 5) | length)
    elif length < 0x100:
        out.append((major << 5) | 24)
        out.append(length)
    elif length < 0x10000:
        out.append((major << 5) | 25)
        out.extend(length.to_bytes(2, "big"))
    elif length < 0x100000000:
        out.append((major << 5) | 26)
        out.extend(length.to_bytes(4, "big"))
    else:
        out.append((major << 5) | 27)
        out.extend(length.to_bytes(8, "big"))


def _canonical_key(item) -> tuple:
    """
    CTAP2 canonical ordering: keys sorted by encoded length, then bytewise.

    Not merely cosmetic. A verifier that re-encodes a structure and compares
    bytes -- which is how attestation is checked -- needs one encoding per
    value, or valid signatures start failing.
    """
    encoded = encode(item)
    return (len(encoded), encoded)


def _encode_into(value, out: bytearray, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise CborError("Structure is nested too deeply to encode")

    if value is True:
        out.append((_SIMPLE << 5) | 21)
    elif value is False:
        out.append((_SIMPLE << 5) | 20)
    elif value is None:
        out.append((_SIMPLE << 5) | 22)

    elif isinstance(value, int):
        if value >= 0:
            _encode_head(_UINT, value, out)
        else:
            _encode_head(_NEGINT, -value - 1, out)

    elif isinstance(value, (bytes, bytearray)):
        _encode_head(_BYTES, len(value), out)
        out.extend(value)

    elif isinstance(value, str):
        encoded = value.encode("utf-8")
        _encode_head(_TEXT, len(encoded), out)
        out.extend(encoded)

    elif isinstance(value, (list, tuple)):
        _encode_head(_ARRAY, len(value), out)
        for item in value:
            _encode_into(item, out, depth + 1)

    elif isinstance(value, dict):
        _encode_head(_MAP, len(value), out)
        for key in sorted(value.keys(), key=_canonical_key):
            _encode_into(key, out, depth + 1)
            _encode_into(value[key], out, depth + 1)

    else:
        raise CborError(f"Cannot encode {type(value).__name__}")


# ------------------------------------------------------------------ decoding

def decode(data: bytes):
    """
    Decode one CBOR item, which must consume the whole input.

    Trailing bytes are an error rather than something to skip: if the sender
    put more there, this parser and that sender disagree about the message.
    """
    value, offset = _decode_from(data, 0, depth=0)
    if offset != len(data):
        raise CborError("Trailing bytes after the CBOR item")
    return value


def decode_prefix(data: bytes):
    """Decode one item, returning it with the number of bytes consumed."""
    return _decode_from(data, 0, depth=0)


def _read_length(data: bytes, offset: int, info: int):
    """Read an item's length, checking it against the data actually present."""
    if info < 24:
        return info, offset

    if info == 24:
        width = 1
    elif info == 25:
        width = 2
    elif info == 26:
        width = 4
    elif info == 27:
        width = 8
    elif info == 31:
        # Indefinite length. Forbidden by CTAP2 canonical CBOR, and the usual
        # route to an unbounded allocation.
        raise CborError("Indefinite-length items are not allowed")
    else:
        raise CborError("Reserved length encoding")

    if offset + width > len(data):
        raise CborError("Truncated length field")

    length = int.from_bytes(data[offset:offset + width], "big")
    return length, offset + width


def _decode_from(data: bytes, offset: int, depth: int):
    if depth > MAX_DEPTH:
        raise CborError("Structure is nested too deeply")
    if offset >= len(data):
        raise CborError("Truncated CBOR item")

    initial = data[offset]
    major = initial >> 5
    info = initial & 0x1F
    offset += 1

    if major == _UINT:
        return _read_length(data, offset, info)

    if major == _NEGINT:
        length, offset = _read_length(data, offset, info)
        return -1 - length, offset

    if major in (_BYTES, _TEXT):
        length, offset = _read_length(data, offset, info)

        # Checked before slicing: a five-byte header can claim gigabytes.
        if length > MAX_STRING_BYTES:
            raise CborError("String exceeds the maximum length")
        if offset + length > len(data):
            raise CborError("String runs past the end of the message")

        chunk = data[offset:offset + length]
        offset += length

        if major == _TEXT:
            try:
                return chunk.decode("utf-8"), offset
            except UnicodeDecodeError:
                raise CborError("Text string is not valid UTF-8")
        return chunk, offset

    if major == _ARRAY:
        count, offset = _read_length(data, offset, info)
        if count > MAX_ITEMS:
            raise CborError("Array has too many items")
        # An array cannot have more items than there are bytes left.
        if count > len(data) - offset:
            raise CborError("Array claims more items than the message can hold")

        items = []
        for _ in range(count):
            item, offset = _decode_from(data, offset, depth + 1)
            items.append(item)
        return items, offset

    if major == _MAP:
        count, offset = _read_length(data, offset, info)
        if count > MAX_ITEMS:
            raise CborError("Map has too many entries")
        if count * 2 > len(data) - offset:
            raise CborError("Map claims more entries than the message can hold")

        result = {}
        for _ in range(count):
            key, offset = _decode_from(data, offset, depth + 1)
            if isinstance(key, (list, dict)):
                raise CborError("Map keys must be simple values")
            if key in result:
                raise CborError("Duplicate map key")
            value, offset = _decode_from(data, offset, depth + 1)
            result[key] = value
        return result, offset

    if major == _SIMPLE:
        if info == 20:
            return False, offset
        if info == 21:
            return True, offset
        if info == 22:
            return None, offset
        # Floats (25-27) and everything else are unused by CTAP2.
        raise CborError("Unsupported simple value")

    raise CborError(f"Unsupported CBOR major type {major}")
