"""
NIST P-256 (secp256r1) ECDSA, in pure Python.

Why this exists
---------------
WebAuthn's mandatory algorithm is ES256: ECDSA over P-256 with SHA-256. Every
relying party asks for it (COSE algorithm -7); a handful also accept RS256. The
Bitcoin curve, secp256k1, has a COSE identifier (-47, "ES256K") but essentially
no browser or RP support, so an authenticator offering only that would be
refused at registration.

SeedSigner's crypto is embit, which is secp256k1 only, and the image ships no
general-purpose crypto library. Rather than add one -- `cryptography` means
cross-compiling a Rust extension into a Buildroot image -- P-256 is implemented
here directly. It is about 150 lines of arithmetic with no dependencies.

Speed
-----
A scalar multiplication measures ~48 ms on a desktop, which extrapolates to
roughly 1-2 seconds on a Pi Zero's 1 GHz ARM11. A registration needs two (one to
derive the key, one to sign) and an assertion the same. That is slow next to a
YubiKey's milliseconds, but the user is holding down a button for user presence
anyway, and it is far inside the browser's timeout.

Signing is deterministic (RFC 6979), so no random number generator is involved
and the output is reproducible -- which is what lets this be tested against
published vectors rather than only against itself.
"""
import hashlib
import hmac


# --------------------------------------------------------------- curve constants

# y^2 = x^3 + ax + b  over F_p, per FIPS 186-4 D.1.2.3
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

# Base point
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G = (GX, GY)

# Order of G
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

# Byte length of a coordinate or scalar
FIELD_BYTES = 32


class P256Error(Exception):
    pass


# ------------------------------------------------------------------ curve maths
#
# Affine coordinates with modular inversion per addition. Jacobian coordinates
# would be several times faster, but this is short enough to read and check by
# eye, which matters more here than shaving a second off a button press.

def _inverse(value: int, modulus: int = P) -> int:
    return pow(value, modulus - 2, modulus)


def point_add(p, q):
    """Add two points on the curve. None is the point at infinity."""
    if p is None:
        return q
    if q is None:
        return p

    x1, y1 = p
    x2, y2 = q

    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if p == q:
        slope = (3 * x1 * x1 + A) * _inverse(2 * y1) % P
    else:
        slope = (y2 - y1) * _inverse(x2 - x1) % P

    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k: int, point=G):
    """Scalar multiplication, double-and-add."""
    if k % N == 0:
        return None
    if k < 0:
        raise P256Error("Negative scalar")

    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def is_on_curve(point) -> bool:
    if point is None:
        return True
    x, y = point
    return (y * y - x * x * x - A * x - B) % P == 0


# ------------------------------------------------------------------ keys

def public_key(private_key: int):
    """Public point for a private scalar."""
    validate_private_key(private_key)
    return point_mul(private_key)


def validate_private_key(private_key: int) -> int:
    if not 1 <= private_key < N:
        raise P256Error("Private key out of range")
    return private_key


def private_key_from_bytes(data: bytes) -> int:
    """
    Turn 32 bytes of entropy into a valid private scalar.

    Rejects the vanishingly unlikely out-of-range values rather than reducing
    mod N, because reduction would bias the key.
    """
    if len(data) != FIELD_BYTES:
        raise P256Error(f"Expected {FIELD_BYTES} bytes")
    return validate_private_key(int.from_bytes(data, "big"))


def encode_point(point) -> bytes:
    """Uncompressed SEC1 encoding: 0x04 || X || Y."""
    if point is None:
        raise P256Error("Cannot encode the point at infinity")
    x, y = point
    return b"\x04" + x.to_bytes(FIELD_BYTES, "big") + y.to_bytes(FIELD_BYTES, "big")


def point_coordinates(point):
    """X and Y as fixed-width bytes, which is what COSE keys want."""
    x, y = point
    return x.to_bytes(FIELD_BYTES, "big"), y.to_bytes(FIELD_BYTES, "big")


# ------------------------------------------------------------------ RFC 6979

def _bits2int(data: bytes) -> int:
    value = int.from_bytes(data, "big")
    excess = len(data) * 8 - N.bit_length()
    return value >> excess if excess > 0 else value


def _int2octets(value: int) -> bytes:
    return value.to_bytes(FIELD_BYTES, "big")


def _bits2octets(data: bytes) -> bytes:
    reduced = _bits2int(data) % N
    return _int2octets(reduced)


def deterministic_nonce(private_key: int, digest: bytes) -> int:
    """
    RFC 6979 deterministic k, using SHA-256.

    Deterministic rather than random on purpose: a hardware wallet with a weak
    or backdoored RNG leaks its private key through ECDSA signatures, and this
    removes the RNG from the equation entirely. It also makes the output
    testable against published vectors.
    """
    key_octets = _int2octets(private_key)
    digest_octets = _bits2octets(digest)

    v = b"\x01" * 32
    k = b"\x00" * 32

    k = hmac.new(k, v + b"\x00" + key_octets + digest_octets, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + key_octets + digest_octets, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = _bits2int(v)
        if 1 <= candidate < N:
            return candidate

        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


# ------------------------------------------------------------------ signing

def sign_digest(private_key: int, digest: bytes):
    """Sign a 32-byte digest. Returns (r, s) with s normalised to the low half."""
    validate_private_key(private_key)
    if len(digest) != 32:
        raise P256Error("Expected a 32-byte digest")

    e = _bits2int(digest)

    while True:
        k = deterministic_nonce(private_key, digest)
        point = point_mul(k)
        if point is None:
            continue

        r = point[0] % N
        if r == 0:
            continue

        s = (_inverse(k, N) * (e + r * private_key)) % N
        if s == 0:
            continue

        # Low-S. Not required by ECDSA, but it makes signatures canonical, and
        # some verifiers reject the high form.
        if s > N // 2:
            s = N - s

        return (r, s)


def sign(private_key: int, message: bytes):
    """Sign a message, hashing it with SHA-256 first."""
    return sign_digest(private_key, hashlib.sha256(message).digest())


def verify_digest(point, digest: bytes, signature) -> bool:
    """
    Verify a signature. Not needed by an authenticator -- included so the tests
    can check signatures independently rather than only comparing to fixtures.
    """
    r, s = signature
    if not (1 <= r < N and 1 <= s < N):
        return False
    if not is_on_curve(point):
        return False

    e = _bits2int(digest)
    w = _inverse(s, N)
    u1 = (e * w) % N
    u2 = (r * w) % N

    result = point_add(point_mul(u1), point_mul(u2, point))
    if result is None:
        return False

    return result[0] % N == r


# ------------------------------------------------------------------ DER

def encode_der_signature(signature) -> bytes:
    """
    ASN.1 DER SEQUENCE { INTEGER r, INTEGER s }.

    WebAuthn assertions carry ES256 signatures in this form, not as raw r||s.
    """
    def encode_integer(value: int) -> bytes:
        raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        # A leading 0x80+ byte would read as negative, so pad it.
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return b"\x02" + bytes([len(raw)]) + raw

    r, s = signature
    body = encode_integer(r) + encode_integer(s)
    return b"\x30" + bytes([len(body)]) + body


def decode_der_signature(der: bytes):
    """Inverse of `encode_der_signature`, for the tests."""
    if len(der) < 8 or der[0] != 0x30:
        raise P256Error("Not a DER SEQUENCE")
    if der[1] != len(der) - 2:
        raise P256Error("Bad DER length")

    offset = 2
    values = []
    for _ in range(2):
        if der[offset] != 0x02:
            raise P256Error("Expected a DER INTEGER")
        length = der[offset + 1]
        values.append(int.from_bytes(der[offset + 2:offset + 2 + length], "big"))
        offset += 2 + length

    if offset != len(der):
        raise P256Error("Trailing DER bytes")

    return tuple(values)
