"""
SeedPass identities: SLIP-0013 authentication from the same seed.

Separate from `seedpass.py` in every way that matters. Passwords derive through
BIP-85 at `m/83696968'/128169'/...`; identities derive through SLIP-0013 at
`m/13'/A'/B'/C'/D'`. Different purpose branches of the same seed, so the two
cannot collide and neither affects the other.

What SLIP-0013 gives us
-----------------------
It is not just a derivation path -- it is a complete challenge-response
authentication protocol, and it is the closest thing to a published standard for
what FIDO2 does with a hardware key:

  1. The service sends an identity (URI + index), a *hidden* challenge (random
     bytes) and a *visual* challenge (human-readable text, e.g. a timestamp).
  2. The signer derives the key for that URI, signs
     `sha256(hidden) || sha256(visual)` with Bitcoin message signing, and
     returns the signature with the public key.
  3. The service creates an account the first time it sees a public key, and
     logs the user in every time after.

The visual challenge is the point of contact with the user: it is displayed on
the SeedSigner screen alongside the URI, so an approval is something a person
actually sees. That is weaker than FIDO2 -- where the browser supplies the
origin and the user cannot be fooled -- but it is designed in rather than
invented here.

Labels and URIs
---------------
The device offers two ways to name an identity, but there is only one derivation
underneath. A real service is addressed by its URI. A bare service name is
turned into `seedpass://<label>`, which is a valid RFC 3986 URI, so it goes
through the standard unmodified. SLIP-0013's `index` is the rotation counter, so
rotation comes from the spec rather than being bolted on.

The upshot: identities named by URI are interoperable with any other SLIP-0013
implementation (Trezor's, for instance), and identities named by label keep the
same mental model as passwords.
"""
import hashlib
import struct

from binascii import hexlify
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlparse

from seedsigner.models.seedpass import (
    MAX_COUNTER,
    SeedPassError,
    normalize_label,
    validate_counter,
)


SLIP13_PURPOSE = 13

# Same version namespace as the password payloads; the path segment distinguishes
# them. See SPEC.md.
SEEDPASS_VERSION = 1

# Scheme used when the user names an identity by service name rather than URI.
# A valid RFC 3986 URI, so SLIP-0013 applies unchanged.
LABEL_URI_SCHEME = "seedpass"

# SLIP-0013 bounds these at 64 bytes / 64 characters.
MAX_HIDDEN_CHALLENGE_BYTES = 64
MAX_VISUAL_CHALLENGE_CHARS = 64

# Anything longer is a sign the QR is not what we think it is.
MAX_URI_LENGTH = 256


class IdentityError(SeedPassError):
    """Raised for a malformed identity, URI or challenge."""


def uri_for_label(label: str, ) -> str:
    """
    Turn a service name into the URI SLIP-0013 derives from.

    `gmail` becomes `seedpass://gmail`. The label is normalized with exactly the
    same rules as a password label, so a user who types `Gmail` gets the same
    identity as one who types `gmail` -- and the same normalization they are
    already used to.

    Normalization failures are re-raised as IdentityError so that everything
    thrown by this module is one type; callers should not have to know that
    label rules are borrowed from the password code.
    """
    try:
        return f"{LABEL_URI_SCHEME}://{normalize_label(label)}"
    except SeedPassError as e:
        raise IdentityError(str(e))


def label_for_uri(uri: str) -> str:
    """Inverse of `uri_for_label`, or None if this is not a label-style URI."""
    if not uri.startswith(f"{LABEL_URI_SCHEME}://"):
        return None
    return uri[len(LABEL_URI_SCHEME) + 3:]


def validate_uri(uri: str) -> str:
    """
    Check that a URI is well-formed enough to derive from.

    SLIP-0013 says RFC 3986 `proto://[user@]host[:port][/path]`. We do not try
    to be a full RFC 3986 validator -- the derivation hashes the raw string, so
    any string "works" -- but a URI with no scheme or no host is almost always a
    mistyped entry rather than an intended identity, and silently deriving a
    different key from it would be worse than refusing.
    """
    if not uri:
        raise IdentityError("Empty URI")
    if len(uri) > MAX_URI_LENGTH:
        raise IdentityError(f"URI exceeds {MAX_URI_LENGTH} chars")

    parsed = urlparse(uri)
    if not parsed.scheme:
        raise IdentityError("URI has no scheme (expected e.g. https://...)")
    if not parsed.netloc:
        raise IdentityError("URI has no host")

    return uri


def slip13_path(uri: str, index: int = 0) -> list:
    """
    The SLIP-0013 derivation path for an identity, as raw BIP-32 child numbers.

    From the spec:

        1. concatenate `index` (little endian uint32) with the URI
        2. sha256 it
        3. truncate to 128 bits
        4. split into four little-endian uint32 A, B, C, D
        5. OR each with 0x80000000 to harden
        6. derive m/13'/A'/B'/C'/D'

    Returns the five child numbers with hardening already applied, so the caller
    can hand them straight to BIP-32. (For secp256k1, SLIP-0010 derivation is
    identical to BIP-32, so no separate implementation is needed.)
    """
    if not 0 <= index <= 0xFFFFFFFF:
        raise IdentityError("Identity index out of range")

    digest = hashlib.sha256(struct.pack("<I", index) + uri.encode("utf-8")).digest()
    a, b, c, d = struct.unpack("<4I", digest[:16])

    hardened = 0x80000000
    return [
        SLIP13_PURPOSE | hardened,
        a | hardened,
        b | hardened,
        c | hardened,
        d | hardened,
    ]


def path_to_string(path: list) -> str:
    """Render a child-number list as `m/13'/A'/B'/C'/D'` for display."""
    parts = ["m"]
    for child in path:
        if child & 0x80000000:
            parts.append(f"{child & 0x7FFFFFFF}'")
        else:
            parts.append(str(child))
    return "/".join(parts)


def challenge_digest(hidden: bytes, visual: str) -> bytes:
    """
    The bytes SLIP-0013 actually signs: sha256(hidden) || sha256(visual).

    Note this is the *input* to Bitcoin message signing, which applies its own
    magic-prefixed double hash on top. Do not sign the challenges directly.
    """
    if len(hidden) > MAX_HIDDEN_CHALLENGE_BYTES:
        raise IdentityError(
            f"Hidden challenge exceeds {MAX_HIDDEN_CHALLENGE_BYTES} bytes"
        )
    if len(visual) > MAX_VISUAL_CHALLENGE_CHARS:
        raise IdentityError(
            f"Visual challenge exceeds {MAX_VISUAL_CHALLENGE_CHARS} chars"
        )

    return hashlib.sha256(hidden).digest() + hashlib.sha256(visual.encode("utf-8")).digest()


@dataclass
class Identity:
    """A derived identity. Holds a public key only -- never the private key."""

    uri: str
    index: int
    path: list
    public_key: str          # 33-byte compressed pubkey, hex
    address: str             # p2wpkh address, as SLIP-0013 returns
    fingerprint: str         # master fingerprint of the parent seed

    @property
    def label(self) -> str:
        """The service name, if this identity was named by label."""
        return label_for_uri(self.uri)

    @property
    def derivation_path(self) -> str:
        return path_to_string(self.path)

    def describe(self) -> str:
        """Human-readable, and deliberately shows the URI: it is what was signed."""
        return self.label or self.uri

    def to_uri(self) -> str:
        """
        Payload for the public-key export QR.

            seedpass://v1/pubkey?fp=..&idx=..&id=..&pk=..&addr=..

        `id` is the identity URI, percent-encoded. A service stores `pk` and
        recognises the user by it on subsequent logins.
        """
        parts = [
            f"fp={self.fingerprint}",
            f"idx={self.index}",
            "id=" + quote(self.uri, safe=""),
            f"pk={self.public_key}",
            f"addr={self.address}",
        ]
        return f"seedpass://v{SEEDPASS_VERSION}/pubkey?" + "&".join(parts)


def derive_identity(seed_bytes: bytes,
                    uri: str = None,
                    label: str = None,
                    index: int = 0) -> Identity:
    """
    Derive the identity for a URI (or a service name) at a rotation index.

    Supply either `uri` for a real service, or `label` for a bare service name,
    which is turned into `seedpass://<label>`.
    """
    if (uri is None) == (label is None):
        raise IdentityError("Supply either a URI or a label, not both")

    if label is not None:
        try:
            index = validate_counter(index)
        except SeedPassError as e:
            raise IdentityError(str(e))
        uri = uri_for_label(label)
    else:
        uri = validate_uri(uri)
        if not 0 <= index <= MAX_COUNTER:
            raise IdentityError(f"Index must be 0-{MAX_COUNTER}")

    from embit import bip32, script
    from embit.networks import NETWORKS

    root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS["main"]["xprv"])

    path = slip13_path(uri, index)
    node = root
    for child in path:
        node = node.derive([child])

    public_key = hexlify(node.key.get_public_key().serialize()).decode("utf-8")
    address = script.p2wpkh(node.key.get_public_key()).address()

    return Identity(
        uri=uri,
        index=index,
        path=path,
        public_key=public_key,
        address=address,
        fingerprint=hexlify(root.child(0).fingerprint).decode("utf-8"),
    )


def sign_challenge(seed_bytes: bytes,
                   uri: str,
                   hidden: bytes,
                   visual: str,
                   index: int = 0) -> str:
    """
    Sign a SLIP-0013 challenge. Returns a base64 Bitcoin message signature.

    Reuses SeedSigner's own `embit_utils.sign_message`, so the signature format
    is exactly what the device already produces for message signing and is
    verifiable with any Bitcoin library.
    """
    from seedsigner.helpers import embit_utils

    path = slip13_path(uri, index)
    digest = challenge_digest(hidden, visual)

    return embit_utils.sign_message(
        seed_bytes=seed_bytes,
        derivation=path_to_string(path),
        msg=digest,
    )


def parse_auth_request(payload: str) -> dict:
    """
    Parse a service's authentication request QR.

        seedpass://v1/auth?id=<uri>&idx=<n>&h=<hex>&v=<text>

    `h` is the hidden challenge as hex, `v` the visual challenge shown to the
    user. Both are bounded by SLIP-0013.
    """
    prefix = f"seedpass://v{SEEDPASS_VERSION}/auth?"
    if not payload.startswith(prefix):
        raise IdentityError("Not a SeedPass authentication request")

    out = {"index": 0, "hidden": b"", "visual": ""}
    for pair in payload[len(prefix):].split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        value = unquote(value)

        if key == "id":
            out["uri"] = validate_uri(value)
        elif key == "idx":
            if not value.isdigit():
                raise IdentityError("Bad index")
            out["index"] = int(value)
        elif key == "h":
            try:
                out["hidden"] = bytes.fromhex(value)
            except ValueError:
                raise IdentityError("Hidden challenge is not valid hex")
        elif key == "v":
            out["visual"] = value

    if "uri" not in out:
        raise IdentityError("Request names no identity")

    # Bounds-check now rather than at signing time, so a malformed request is
    # rejected before anything is shown to the user as approvable.
    challenge_digest(out["hidden"], out["visual"])

    return out
