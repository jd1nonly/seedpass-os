"""
A FIDO2 session armed for one relying party, so the seed can be dropped before
the cable goes in.

The idea
--------
CTAP2 normally needs the seed present for the whole USB conversation, because
the host says which credential it wants and the device derives it on the spot.
That means a bug in the USB parsing path reaches the seed.

Here the order is inverted. The relying party is chosen *before* any cable is
connected -- scanned from a QR the companion app produces -- so the credential
key can be derived first and the seed released. What remains is a single P-256
private scalar, useful for exactly one site.

    1. SeedPasser turns a URL into a QR:  seedpass://v1/fido2?rp=github.com
    2. SeedSigner scans it, picks a seed, derives that credential
    3. The seed is released; only the credential remains
    4. Cable in. Requests for any other RP are refused
    5. Cable out; the session ends

Why the seed stays loaded
-------------------------
An earlier design tried to derive the credential, drop the seed, and only then
connect the cable. It does not work. FIDO2 credentials are permanent -- the
relying party stores the public key at registration and expects the same key at
every login -- so the derived key would have to survive the power cycle, and
there is nowhere to put it. The screen dies with the power, the SD card cannot
be reliably erased because of flash wear-levelling, and photographing the QR
makes a lasting copy of a long-lived secret on the very device that was supposed
not to hold keys. The scheme needed a second display that does not exist.

So the seed is resident during a USB session, as it is in every hardware wallet
and as a YubiKey's secrets are whenever it is plugged in. What this class still
does is narrow what a session can be used for:

    1. The relying party is chosen *before* the cable, by scanning a QR the
       companion app produces from the site's URL.
    2. The credential is derived and shown to the user for approval.
    3. Requests for any other RP are refused for the life of the session,
       whatever the host asks for.

That is a real restriction and worth having on its own. A host cannot enumerate
sites, cannot mint credentials for domains the user never approved, and cannot
quietly swap the RP mid-session. It is not a claim that the seed is unreachable.

The exposure that remains
-------------------------
A bug in the CTAP stack reaches the seed. That stack is deliberately small --
strict CBOR with bounded lengths and no indefinite-length items, framing that
refuses out-of-order and replayed sequence numbers, no CTAP1 path, no PIN
protocol, no credential management -- and user presence is required before any
key is touched. But it is code an attacker can drive directly over USB, which
nothing else on this device is.

Registration and login differ
-----------------------------
Registering needs only the RP: the device invents the nonce. Logging in needs
that same nonce, because the credential key derives from it -- and the nonce
normally arrives inside the credential ID, over USB, after the seed is gone. So
for logins the prep QR must carry the nonce, which the companion app records at
registration time from the device's own export QR. The alternative is leaving
the seed loaded, which is what an unarmed session does.
"""
import os

from urllib.parse import quote, unquote

from seedsigner.models.fido2_credential import NONCE_BYTES, Credential


SEEDPASS_VERSION = 1

PREPARE_PREFIX = f"seedpass://v{SEEDPASS_VERSION}/fido2?"
CREDENTIAL_PREFIX = f"seedpass://v{SEEDPASS_VERSION}/fido2cred?"

# A DNS name cannot be longer than this, and the RP ID is one.
MAX_RP_ID_CHARS = 253


class SessionError(Exception):
    pass


def build_prepare_uri(rp_id: str, nonce: bytes = None) -> str:
    """
    The QR the companion app shows for the device to scan.

    Without a nonce this prepares a registration; with one it prepares a login
    for an existing credential.
    """
    validate_rp_id(rp_id)
    uri = PREPARE_PREFIX + "rp=" + quote(rp_id, safe="")
    if nonce is not None:
        if len(nonce) != NONCE_BYTES:
            raise SessionError("Bad nonce length")
        uri += "&n=" + nonce.hex()
    return uri


def parse_prepare_uri(payload: str) -> dict:
    """Parse that QR. Returns {"rp_id": str, "nonce": bytes or None}."""
    if not payload.startswith(PREPARE_PREFIX):
        raise SessionError("Not a SeedPass FIDO2 preparation QR")

    rp_id = None
    nonce = None

    for pair in payload[len(PREPARE_PREFIX):].split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        if key == "rp":
            rp_id = unquote(value)
        elif key == "n":
            try:
                nonce = bytes.fromhex(value)
            except ValueError:
                raise SessionError("Nonce is not valid hex")
            if len(nonce) != NONCE_BYTES:
                raise SessionError("Nonce is the wrong length")

    validate_rp_id(rp_id)
    return {"rp_id": rp_id, "nonce": nonce}


def validate_rp_id(rp_id: str) -> str:
    """
    Check the RP ID before it is shown to the user for approval.

    The whole security of the arming step is the person reading this string and
    recognising the site, so it must not be able to contain anything that makes
    it render deceptively -- control characters, newlines, padding whitespace.
    """
    if not rp_id:
        raise SessionError("Missing RP ID")
    if len(rp_id) > MAX_RP_ID_CHARS:
        raise SessionError("RP ID is too long")
    if rp_id != rp_id.strip():
        raise SessionError("RP ID has surrounding whitespace")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in rp_id):
        raise SessionError("RP ID contains control characters")
    if any(c.isspace() for c in rp_id):
        raise SessionError("RP ID contains whitespace")
    return rp_id


def build_credential_uri(rp_id: str, nonce: bytes, credential_id: bytes) -> str:
    """
    Shown by the device after registering, for the companion app to record.

    Carries no secret: the nonce and credential ID are both public, and the
    relying party already holds the credential ID. Recording them is what makes
    a later armed login possible.
    """
    return (
        CREDENTIAL_PREFIX
        + "rp=" + quote(rp_id, safe="")
        + "&n=" + nonce.hex()
        + "&id=" + credential_id.hex()
    )


def parse_credential_uri(payload: str) -> dict:
    if not payload.startswith(CREDENTIAL_PREFIX):
        raise SessionError("Not a SeedPass FIDO2 credential QR")

    result = {"rp_id": None, "nonce": None, "credential_id": None}
    for pair in payload[len(CREDENTIAL_PREFIX):].split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        try:
            if key == "rp":
                result["rp_id"] = unquote(value)
            elif key == "n":
                result["nonce"] = bytes.fromhex(value)
            elif key == "id":
                result["credential_id"] = bytes.fromhex(value)
        except ValueError:
            raise SessionError(f"Field {key} is not valid hex")

    validate_rp_id(result["rp_id"])
    return result


class ArmedSession:
    """
    One credential, for one relying party, with the seed released.

    Constructed while the seed is still available; afterwards it holds only the
    derived credential. `matches` gates every request so the session cannot be
    used for a site other than the one approved.
    """

    def __init__(self, seed_bytes: bytes, rp_id: str, nonce: bytes = None):
        validate_rp_id(rp_id)

        self.rp_id = rp_id
        self.nonce = nonce if nonce is not None else os.urandom(NONCE_BYTES)
        self.is_registration = nonce is None

        # Derived here, while the seed is in hand. This is the only moment the
        # session touches it.
        self._credential = Credential(seed_bytes, rp_id, self.nonce)


    @property
    def credential_id(self) -> bytes:
        return self._credential.credential_id

    def matches(self, rp_id: str, credential_id: bytes = None) -> bool:
        """
        Whether this session may answer a request.

        The RP must match what the user approved. If the host names a specific
        credential it must be this one -- checked bytewise, since the MAC cannot
        be verified without the seed.
        """
        if rp_id != self.rp_id:
            return False
        if credential_id is not None and credential_id != self.credential_id:
            return False
        return True

    def credential_for(self, rp_id: str, credential_id: bytes = None):
        """The credential, or None if the request is for something else."""
        if not self.matches(rp_id, credential_id):
            return None
        return self._credential

    def to_credential_uri(self) -> str:
        return build_credential_uri(self.rp_id, self.nonce, self.credential_id)

    def describe(self) -> str:
        action = "register" if self.is_registration else "sign in"
        return f"{self.rp_id} ({action})"

