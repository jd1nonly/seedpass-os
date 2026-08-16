"""
SeedPass: deterministic password derivation for SeedSigner.

Pure, GUI-free derivation logic. Everything in this module is a deterministic
function of (seed_bytes, label|index, counter, fmt), so the exact same password
can be re-derived by any other implementation that follows SPEC.md.

Derivation chain
----------------
    BIP-39 mnemonic (+ optional passphrase)
        -> BIP-39 seed bytes (512 bits)
        -> BIP-32 master key (xprv)
        -> BIP-85 (app 128169', "HEX") raw entropy at
               m/83696968'/128169'/{num_bytes}'/{index}'
        -> big-endian integer
        -> fixed-width base58 (Bitcoin alphabet)
        -> "!2" appended  ==  the password

Two formats:

    b58-256   44 base58 chars + "!2"  =  46 chars, 256 bits
    b58-16    14 base58 chars + "!2"  =  16 chars,  82 bits

base58 rather than base64 because the Bitcoin alphabet omits 0, O, I and l --
the four glyph pairs that make a hand-transcribed password silently wrong. It
costs a little density (5.86 bits/char against 6) and buys legibility.

The "!2" suffix guarantees a digit and a symbol, which many sites demand. Upper
and lowercase are guaranteed by the policy walk in `derive_password` rather than
by mangling the encoding.

IMPORTANT: none of these functions persist anything. Nothing is ever written to
the MicroSD card.
"""
import hashlib
import hmac
import unicodedata

from binascii import hexlify
from dataclasses import dataclass
from urllib.parse import quote, unquote


# Bump only on a breaking change to the derivation or QR payload format.
SEEDPASS_VERSION = 1

# Domain-separation tag for label -> BIP-85 index. Public constant; the index is
# not a secret, only the seed is.
INDEX_HMAC_KEY = b"SeedPass/v1/index"

# BIP-85 hardened index space is 0 .. 2^31 - 1
BIP85_MAX_INDEX = 2**31 - 1

# BIP-85 application number for raw entropy ("HEX" in the BIP text)
BIP85_APP_HEX = 128169

# Bitcoin's base58 alphabet: no 0, O, I or l.
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {char: i for i, char in enumerate(B58_ALPHABET)}

# Appended verbatim so every password contains a digit and a symbol.
PASSWORD_SUFFIX = "!2"

# Safety valve on the policy walk. A candidate fails the upper/lower check about
# once in 1,000 tries for the short format, so this is unreachable in practice.
MAX_INDEX_WALK = 1000

# Chars allowed in a normalized service label (keeps QR payloads and cross-device
# typing unambiguous).
LABEL_ALLOWED_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789 .-_+@:/")
LABEL_MAX_LENGTH = 64

MAX_COUNTER = 999


class SeedPassError(Exception):
    pass


class PasswordFormat:
    """
    The two output shapes.

    `FULL` is the default and carries the whole 256 bits. `SHORT` exists only
    for sites that cap passwords at 16 characters -- 16 characters cannot hold
    256 bits, so it is a genuinely weaker password and is labelled as such.
    """

    FULL = "b58-256"
    SHORT = "b58-16"

    ALL = [FULL, SHORT]

    # fmt -> (BIP-85 num_bytes, base58 chars, effective bits)
    _PARAMS = {
        #      bytes  b58 chars  bits
        FULL:  (32,   44,        256),
        SHORT: (16,   14,        82),
    }

    @staticmethod
    def _params(fmt: str):
        try:
            return PasswordFormat._PARAMS[fmt]
        except KeyError:
            raise SeedPassError(f"Unknown password format: {fmt}")

    @staticmethod
    def num_bytes(fmt: str) -> int:
        return PasswordFormat._params(fmt)[0]

    @staticmethod
    def num_b58_chars(fmt: str) -> int:
        return PasswordFormat._params(fmt)[1]

    @staticmethod
    def num_bits(fmt: str) -> int:
        return PasswordFormat._params(fmt)[2]

    @staticmethod
    def char_length(fmt: str) -> int:
        """Passwords are a fixed length for a given format."""
        return PasswordFormat.num_b58_chars(fmt) + len(PASSWORD_SUFFIX)

    @staticmethod
    def display_name(fmt: str) -> str:
        return {
            PasswordFormat.FULL: "Full: 46 char",
            PasswordFormat.SHORT: "Short: 16 char",
        }.get(fmt, fmt)


DEFAULT_FORMAT = PasswordFormat.FULL


def normalize_label(label: str) -> str:
    """
    Canonicalize a service label so that "Gmail", " gmail " and "GMAIL" all map
    to the same BIP-85 index.

    NFKD -> casefold -> collapse whitespace -> strip -> validate charset.
    """
    if label is None:
        raise SeedPassError("Label is required")

    normalized = unicodedata.normalize("NFKD", label)
    normalized = normalized.casefold()
    normalized = " ".join(normalized.split())

    if not normalized:
        raise SeedPassError("Label is empty")

    if len(normalized) > LABEL_MAX_LENGTH:
        raise SeedPassError(f"Label exceeds {LABEL_MAX_LENGTH} chars")

    invalid = sorted(set(normalized) - LABEL_ALLOWED_CHARS)
    if invalid:
        raise SeedPassError(f"Label has unsupported chars: {''.join(invalid)}")

    return normalized


def index_from_label(label: str, counter: int = 0) -> int:
    """
    Map a service label + rotation counter to a BIP-85 hardened child index.

    Seed-independent by design: the index is derivable without the seed, so a
    companion app can show which index a label maps to without holding secrets.

    index = int(HMAC-SHA256(INDEX_HMAC_KEY, label || 0x00 || counter)[0:4]) & 0x7FFFFFFF
    """
    counter = validate_counter(counter)
    normalized = normalize_label(label)

    msg = normalized.encode("utf-8") + b"\x00" + str(counter).encode("ascii")
    digest = hmac.new(INDEX_HMAC_KEY, msg, hashlib.sha256).digest()

    return int.from_bytes(digest[:4], "big") & BIP85_MAX_INDEX


def validate_counter(counter: int) -> int:
    try:
        counter = int(counter)
    except (TypeError, ValueError):
        raise SeedPassError("Counter must be a number")
    if not 0 <= counter <= MAX_COUNTER:
        raise SeedPassError(f"Counter must be 0-{MAX_COUNTER}")
    return counter


def validate_index(index: int) -> int:
    try:
        index = int(index)
    except (TypeError, ValueError):
        raise SeedPassError("Index must be a number")
    if not 0 <= index <= BIP85_MAX_INDEX:
        raise SeedPassError("Index must be 0 to 2^31-1")
    return index


def _bip85_entropy(seed_bytes: bytes, num_bytes: int, index: int) -> bytes:
    """
    Raw BIP-85 entropy at m/83696968'/128169'/{num_bytes}'/{index}'.
    """
    # Imported lazily: embit is slow to import and Views may never need it.
    from embit import bip32, bip85
    from embit.networks import NETWORKS

    root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS["main"]["xprv"])
    entropy = bip85.derive_entropy(root, BIP85_APP_HEX, [num_bytes, index])
    return entropy[:num_bytes]


def b58_encode_fixed(value: int, num_chars: int) -> str:
    """
    Encode `value` as exactly `num_chars` base58 characters, big-endian.

    Fixed width, so the leading character is a literal "1" when the value is
    small rather than being stripped. If `value` needs more than `num_chars`
    digits, the high digits are discarded -- i.e. the result is
    `value mod 58**num_chars`. Callers that must not lose bits are responsible
    for sizing `num_chars` accordingly (see PasswordFormat).
    """
    if value < 0:
        raise SeedPassError("Cannot base58-encode a negative value")

    chars = []
    for _ in range(num_chars):
        value, remainder = divmod(value, 58)
        chars.append(B58_ALPHABET[remainder])
    return "".join(reversed(chars))


def b58_decode(encoded: str) -> int:
    """Inverse of `b58_encode_fixed`, up to the discarded high digits."""
    value = 0
    for char in encoded:
        try:
            value = value * 58 + B58_INDEX[char]
        except KeyError:
            raise SeedPassError(f"Not a base58 character: {char!r}")
    return value


def encode_password(entropy: bytes, fmt: str) -> str:
    """
    Fixed-width base58 of the entropy, with PASSWORD_SUFFIX appended.

    For `FULL`, 44 base58 digits hold 2**257.8, comfortably more than the 256
    bits of entropy, so nothing is lost and the value round-trips exactly.

    For `SHORT`, 14 digits hold 2**82, so only the low 82 bits of the 128-bit
    source survive. That is what 16 characters can carry.
    """
    num_chars = PasswordFormat.num_b58_chars(fmt)
    value = int.from_bytes(entropy, "big")
    return b58_encode_fixed(value, num_chars) + PASSWORD_SUFFIX


def decode_password(password: str, fmt: str = DEFAULT_FORMAT) -> int:
    """
    Recover the integer behind a password. Provided for tests + companion apps.

    For `FULL` this is the full BIP-85 entropy as an integer, so
    `int.to_bytes(32, "big")` gives the original bytes back. For `SHORT` it is
    the truncated value only; the source entropy is not recoverable.
    """
    if not password.endswith(PASSWORD_SUFFIX):
        raise SeedPassError("Password is missing the expected suffix")

    encoded = password[: -len(PASSWORD_SUFFIX)]
    expected = PasswordFormat.num_b58_chars(fmt)
    if len(encoded) != expected:
        raise SeedPassError(f"Expected {expected} base58 chars, got {len(encoded)}")

    return b58_decode(encoded)


def satisfies_charset_policy(password: str) -> bool:
    """
    Whether the password contains at least one uppercase and one lowercase
    letter. Digit and symbol are guaranteed by PASSWORD_SUFFIX.
    """
    return any(c.isupper() for c in password) and any(c.islower() for c in password)


@dataclass
class DerivedPassword:
    """Result of one derivation. Holds secrets; do not log or persist."""

    label: str                      # normalized label, or "" in index mode
    index: int                      # BIP-85 hardened child index actually used
    counter: int                    # rotation counter (label mode only)
    fingerprint: str                # master fingerprint of the parent seed
    password: str                   # the value the user types
    fmt: str = DEFAULT_FORMAT
    base_index: int = 0             # index before any policy walk
    walk_steps: int = 0             # how far the index walked to satisfy policy
    derivation_path: str = ""

    @property
    def is_label_mode(self) -> bool:
        return bool(self.label)

    @property
    def char_length(self) -> int:
        return len(self.password)

    @property
    def num_bits(self) -> int:
        return PasswordFormat.num_bits(self.fmt)

    def chunks(self, size: int) -> list:
        """
        The password split into fixed-size groups for on-screen transcription.
        Display only -- the groups are joined with nothing, not spaces.
        """
        return [self.password[i:i + size] for i in range(0, len(self.password), size)]

    def to_uri(self, include_secret: bool = True) -> str:
        """
        Payload for the export QR. Parsed by the companion app.

            seedpass://v1/secret?fp=..&idx=..&ctr=..&fmt=..&label=..&secret=..
            seedpass://v1/ref?fp=..&idx=..&ctr=..&fmt=..&label=..

        `idx` is the final index, so an app never needs to replay the walk.
        See SPEC.md for the full grammar.
        """
        kind = "secret" if include_secret else "ref"
        parts = [
            f"fp={self.fingerprint}",
            f"idx={self.index}",
            f"ctr={self.counter}",
            f"fmt={self.fmt}",
        ]
        if self.label:
            parts.append("label=" + quote(self.label, safe=""))
        if include_secret:
            parts.append("secret=" + quote(self.password, safe=""))

        return f"seedpass://v{SEEDPASS_VERSION}/{kind}?" + "&".join(parts)


def parse_uri(uri: str) -> dict:
    """Inverse of DerivedPassword.to_uri(). Provided for tests + companion apps."""
    prefix = f"seedpass://v{SEEDPASS_VERSION}/"
    if not uri.startswith(prefix):
        raise SeedPassError("Not a SeedPass v1 URI")

    remainder = uri[len(prefix):]
    kind, _, query = remainder.partition("?")
    if kind not in ("secret", "ref"):
        raise SeedPassError(f"Unknown SeedPass URI kind: {kind}")

    out = {"kind": kind}
    for pair in query.split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        out[key] = unquote(value)

    for int_key in ("idx", "ctr"):
        if int_key in out:
            out[int_key] = int(out[int_key])

    return out


def get_fingerprint(seed_bytes: bytes) -> str:
    from embit import bip32
    from embit.networks import NETWORKS

    root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS["main"]["xprv"])
    return hexlify(root.child(0).fingerprint).decode("utf-8")


def derive_password(seed_bytes: bytes,
                    label: str = None,
                    index: int = None,
                    counter: int = 0,
                    fmt: str = DEFAULT_FORMAT) -> DerivedPassword:
    """
    Derive one password: fixed-width base58 of BIP-85 entropy, plus the suffix.

    Supply either `label` (label mode) or `index` (advanced mode).

    Label mode enforces the charset policy. If a candidate has no uppercase or
    no lowercase character, the index steps forward by one and we try again.
    Deterministic, so the label alone still regenerates it.

    Index mode does NOT walk: the caller asked for a specific BIP-85 index and
    gets exactly that, so index mode stays bit-for-bit interoperable with any
    other BIP-85 tool.
    """
    if label is None and index is None:
        raise SeedPassError("Supply a label or an index")

    num_bytes = PasswordFormat.num_bytes(fmt)
    fingerprint = get_fingerprint(seed_bytes)

    if label is not None:
        normalized_label = normalize_label(label)
        counter = validate_counter(counter)
        base_index = index_from_label(normalized_label, counter)

        for walk_steps in range(MAX_INDEX_WALK):
            candidate_index = (base_index + walk_steps) & BIP85_MAX_INDEX
            password = encode_password(
                _bip85_entropy(seed_bytes, num_bytes, candidate_index), fmt
            )
            if satisfies_charset_policy(password):
                break
        else:
            # Unreachable in practice; roughly (1/1000) ** 1000.
            raise SeedPassError("Could not find a password satisfying the charset policy")

    else:
        normalized_label = ""
        counter = 0
        base_index = validate_index(index)
        candidate_index = base_index
        walk_steps = 0
        password = encode_password(
            _bip85_entropy(seed_bytes, num_bytes, candidate_index), fmt
        )

    return DerivedPassword(
        label=normalized_label,
        index=candidate_index,
        counter=counter,
        fingerprint=fingerprint,
        password=password,
        fmt=fmt,
        base_index=base_index,
        walk_steps=walk_steps,
        derivation_path=f"m/83696968'/{BIP85_APP_HEX}'/{num_bytes}'/{candidate_index}'",
    )
