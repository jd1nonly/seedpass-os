"""
FIDO2 credentials, derived rather than stored.

A normal authenticator generates a random keypair per site and saves it. This
device saves nothing -- the rootfs is read-only and the whole design rests on
the seed being the only thing that must survive. So credentials are derived:

    credential key = f(seed, rpIdHash, nonce)

and the *credential ID* handed to the relying party carries the nonce. The RP
stores it and hands it back at every login, so the device can re-derive the key
without ever having recorded anything. These are "non-discoverable" (formerly
server-side) credentials in WebAuthn's language.

The obvious attack, and the defence
-----------------------------------
If a credential ID were just a nonce, a hostile host could invent one and ask
the device to derive and sign with a key of the attacker's choosing -- a signing
oracle over an attacker-chosen derivation path. So a credential ID is:

    nonce (16 bytes) || HMAC-SHA256(mac_key, rpIdHash || nonce)[:16]

and the MAC is verified before anything is derived. A credential ID this device
did not issue is rejected. The MAC also binds the credential to its RP, so a
credential ID issued for one site cannot be replayed at another: the rpIdHash
that goes into the MAC comes from the *current* request, and a mismatch fails.

Why P-256 here is a security property, not just a compatibility one
-------------------------------------------------------------------
FIDO2 keys live on P-256; every other key this device derives lives on
secp256k1. Different curves mean a signature produced by the FIDO2 path can
never be a valid Bitcoin signature, whatever bytes a host manages to get signed.
The separation is structural rather than a matter of being careful.

Key separation
--------------
Derivation is one-way (HMAC), not BIP-32 child derivation, so a leaked FIDO2
private key reveals nothing about the seed or any sibling key. Passwords derive
through BIP-85, identities through SLIP-13, credentials through this: three
branches that cannot interact.
"""
import hashlib
import hmac

from seedsigner.models import p256


class CredentialError(Exception):
    pass


# Domain separation, so the three derivations from one seed cannot collide even
# in principle.
_MASTER_INFO = b"SeedPass/v1/fido2/master"
_KEY_INFO = b"SeedPass/v1/fido2/key"
_MAC_INFO = b"SeedPass/v1/fido2/credid"

NONCE_BYTES = 16
MAC_BYTES = 16
CREDENTIAL_ID_BYTES = NONCE_BYTES + MAC_BYTES

# All-zero AAGUID: required when attestation is "none", and it is also the
# honest answer -- this is not a certified authenticator model.
AAGUID = b"\x00" * 16


def _master(seed_bytes: bytes) -> bytes:
    """Root of the FIDO2 branch, one-way from the seed."""
    return hmac.new(_MASTER_INFO, seed_bytes, hashlib.sha256).digest()


def _mac_key(seed_bytes: bytes) -> bytes:
    return hmac.new(_master(seed_bytes), _MAC_INFO, hashlib.sha256).digest()


def rp_id_hash(rp_id: str) -> bytes:
    """SHA-256 of the RP ID, as WebAuthn defines it."""
    if not rp_id:
        raise CredentialError("Missing RP ID")
    return hashlib.sha256(rp_id.encode("utf-8")).digest()


def _credential_mac(seed_bytes: bytes, rp_hash: bytes, nonce: bytes) -> bytes:
    return hmac.new(
        _mac_key(seed_bytes), rp_hash + nonce, hashlib.sha256,
    ).digest()[:MAC_BYTES]


def make_credential_id(seed_bytes: bytes, rp_hash: bytes, nonce: bytes) -> bytes:
    if len(nonce) != NONCE_BYTES:
        raise CredentialError("Bad nonce length")
    return nonce + _credential_mac(seed_bytes, rp_hash, nonce)


def parse_credential_id(seed_bytes: bytes, rp_hash: bytes, credential_id: bytes) -> bytes:
    """
    Recover the nonce from a credential ID, rejecting anything not ours.

    The comparison is constant-time. A timing side channel here would let a host
    forge a credential ID byte by byte, which is exactly the signing oracle the
    MAC exists to prevent.
    """
    if len(credential_id) != CREDENTIAL_ID_BYTES:
        raise CredentialError("Credential ID is the wrong length")

    nonce = credential_id[:NONCE_BYTES]
    presented = credential_id[NONCE_BYTES:]
    expected = _credential_mac(seed_bytes, rp_hash, nonce)

    if not hmac.compare_digest(presented, expected):
        raise CredentialError("Credential ID was not issued by this device for this RP")

    return nonce


def derive_private_key(seed_bytes: bytes, rp_hash: bytes, nonce: bytes) -> int:
    """
    The P-256 private scalar for a credential.

    Retries on the negligible chance the HMAC output is out of range, rather
    than reducing mod N, which would bias the key.
    """
    counter = 0
    while counter < 256:
        material = hmac.new(
            _master(seed_bytes),
            _KEY_INFO + rp_hash + nonce + bytes([counter]),
            hashlib.sha256,
        ).digest()
        try:
            return p256.private_key_from_bytes(material)
        except p256.P256Error:
            counter += 1

    raise CredentialError("Could not derive a valid key")


def cose_public_key(point) -> dict:
    """
    COSE_Key for an ES256 public key, per RFC 8152.

      1: kty = 2 (EC2)      3: alg = -7 (ES256)
     -1: crv = 1 (P-256)   -2: x    -3: y
    """
    x, y = p256.point_coordinates(point)
    return {1: 2, 3: -7, -1: 1, -2: x, -3: y}


class Credential:
    """A derived credential. Holds the private scalar only while in use."""

    def __init__(self, seed_bytes: bytes, rp_id: str, nonce: bytes):
        self.rp_id = rp_id
        self.rp_hash = rp_id_hash(rp_id)
        self.nonce = nonce
        self.credential_id = make_credential_id(seed_bytes, self.rp_hash, nonce)
        self._private_key = derive_private_key(seed_bytes, self.rp_hash, nonce)
        self.public_key = p256.public_key(self._private_key)


    @classmethod
    def from_credential_id(cls, seed_bytes: bytes, rp_id: str, credential_id: bytes):
        """Re-derive a credential the RP handed back. Raises if it is not ours."""
        nonce = parse_credential_id(seed_bytes, rp_id_hash(rp_id), credential_id)
        return cls(seed_bytes, rp_id, nonce)

    def cose_key(self) -> dict:
        return cose_public_key(self.public_key)

    def sign(self, data: bytes) -> bytes:
        """DER-encoded ES256 signature over `data`."""
        digest = hashlib.sha256(data).digest()
        return p256.encode_der_signature(p256.sign_digest(self._private_key, digest))


# ------------------------------------------------------------ authenticatorData

FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04
FLAG_ATTESTED_DATA = 0x40


def authenticator_data(rp_hash: bytes,
                       user_present: bool = True,
                       user_verified: bool = False,
                       sign_count: int = 0,
                       credential=None) -> bytes:
    """
    The authenticatorData structure WebAuthn signs over.

        rpIdHash (32) || flags (1) || signCount (4) || [attested credential data]

    `sign_count` stays at 0, which the spec defines as "not supported". A
    counter would need somewhere to persist, and this device writes nothing. The
    cost is that an RP cannot use counter regression to detect a cloned
    authenticator -- but cloning here means having the seed, at which point the
    counter is the least of the problem.
    """
    if len(rp_hash) != 32:
        raise CredentialError("Bad RP ID hash")

    flags = 0
    if user_present:
        flags |= FLAG_USER_PRESENT
    if user_verified:
        flags |= FLAG_USER_VERIFIED
    if credential is not None:
        flags |= FLAG_ATTESTED_DATA

    data = rp_hash + bytes([flags]) + sign_count.to_bytes(4, "big")

    if credential is not None:
        from seedsigner.models import fido2_cbor

        credential_id = credential.credential_id
        data += (
            AAGUID
            + len(credential_id).to_bytes(2, "big")
            + credential_id
            + fido2_cbor.encode(credential.cose_key())
        )

    return data
