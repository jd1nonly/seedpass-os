"""
SIDO3 -- WebAuthn signing for an air-gapped device, relayed over QR.

The problem it solves
---------------------
FIDO2 is phishing-proof because the *browser* states which site is asking, over
a channel a web page cannot forge. Every QR-only login scheme loses that: the
page supplies the origin, and a phishing page lies. But FIDO2's own transports
-- USB, NFC, BLE -- all require the key holder to be reachable, which an
air-gapped device is not.

SIDO3 takes the origin from Android's Credential Manager instead. A companion
app registers as a passkey provider; when a browser calls WebAuthn, the OS hands
the app the request *and the calling app's origin*. The app holds no keys. It
turns the request into a QR, the air-gapped device signs it, and the app returns
the response to the OS.

    browser -> Android Credential Manager -> companion app
                                                 |
                                            QR   |   QR
                                                 v
                                          air-gapped signer

The origin is browser-attested, so phishing resistance survives. The key never
leaves the signer, which never connects to anything.

Division of labour
------------------
The companion app assembles `clientDataJSON` and hashes it; the signer receives
only the 32-byte hash. That keeps the QR small enough for a single frame -- a
registration response is around 500 characters -- and keeps JSON parsing off the
device, where every parser is attack surface.

The check that matters
----------------------
`rpId` arrives in the request; `origin` comes from the OS. A browser guarantees
they agree, but this device does not have to take that on trust, and a bug in
the relay must not become a phishing hole. So `validate_rp_id_for_origin`
re-does the WebAuthn check here: the RP ID must equal the origin's effective
domain or be a registrable suffix of it. `login.example.com` may claim
`example.com`; it may not claim `example.com.evil.net`, `xample.com`, or `com`.

Naming
------
"SIDO3" is this project's own scheme. It is **not** FIDO3, is not a FIDO
Alliance standard, and no relying party implements it -- the relying party sees
ordinary WebAuthn, because that is what the companion app returns. The name
describes the local arrangement, not a new protocol on the wire.
"""
import hashlib

from urllib.parse import quote, unquote, urlparse

from seedsigner.models.fido2_credential import (
    CREDENTIAL_ID_BYTES,
    NONCE_BYTES,
    Credential,
    CredentialError,
    authenticator_data,
)


SIDO3_VERSION = 3

CREATE_REQUEST_PREFIX = f"sido{SIDO3_VERSION}://v1/create?"
GET_REQUEST_PREFIX = f"sido{SIDO3_VERSION}://v1/get?"
CREATE_RESPONSE_PREFIX = f"sido{SIDO3_VERSION}://v1/created?"
GET_RESPONSE_PREFIX = f"sido{SIDO3_VERSION}://v1/asserted?"

MAX_RP_ID_CHARS = 253
MAX_ORIGIN_CHARS = 512
MAX_USER_NAME_CHARS = 64

# Suffixes no site may claim as its RP ID, because doing so would match every
# site beneath them.
#
# **This is not a complete Public Suffix List.** The real PSL is megabytes and
# changes weekly, which is not something to ship on a device with no network to
# update it. What is here covers bare TLDs and the common multi-label suffixes
# that a partial list would otherwise miss -- `co.uk` was missed by an earlier
# version of exactly this set, which is why the list is now explicit about the
# two-label cases.
#
# The gap is bounded by where this check sits: the browser has already applied
# the real PSL before the request left it, and Android passed it through
# untouched. This is a second line of defence against a compromised relay, not
# the first. A rare public suffix omitted here is a weakened second line, not an
# open door.
_BARE_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "uk", "de",
    "fr", "jp", "cn", "ru", "br", "in", "au", "ca", "eu", "us", "info", "biz",
    "app", "dev", "xyz", "me", "tv", "cc", "pt", "es", "it", "nl", "se", "no",
    "ch", "at", "be", "dk", "fi", "gr", "ie", "pl", "cz", "nz", "za", "mx",
    "ar", "cl", "kr", "tw", "hk", "sg", "il", "tr", "ua", "id", "th", "vn",
}

# Two-label suffixes: the case a naive set misses.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "net.za",
    "com.mx", "com.ar", "com.tr", "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.in", "net.in", "org.in", "gov.in",
    "com.sg", "com.hk", "com.tw", "co.kr", "or.kr",
    "com.pl", "com.ua", "co.il", "com.vn", "co.th", "co.id",
    "com.es", "com.pt", "com.it", "com.de", "com.ru", "org.ru", "net.ru",
}

FORBIDDEN_RP_IDS = _BARE_TLDS | _MULTI_LABEL_SUFFIXES


class Sido3Error(Exception):
    pass


# --------------------------------------------------------------- origin checks

def origin_effective_domain(origin: str) -> str:
    """
    The host of an origin, checked for the properties WebAuthn requires.

    HTTPS only, with localhost as the standard development exception. A phishing
    page served over plain HTTP must not be able to obtain a signature.
    """
    if not origin or len(origin) > MAX_ORIGIN_CHARS:
        raise Sido3Error("Missing or oversized origin")

    parsed = urlparse(origin)

    if parsed.scheme not in ("https", "http"):
        raise Sido3Error(f"Origin scheme must be https, got {parsed.scheme or 'none'}")

    host = parsed.hostname
    if not host:
        raise Sido3Error("Origin has no host")

    if parsed.scheme == "http" and host not in ("localhost", "127.0.0.1"):
        raise Sido3Error("Plain http origins are not accepted")

    return host.lower()


def validate_rp_id_for_origin(rp_id: str, origin: str) -> str:
    """
    The WebAuthn RP ID check, re-done on the signing device.

    A browser already enforces this, and the relay is supposed to pass it
    through untouched -- but "supposed to" is not a security property. Doing it
    here means a bug or a compromise in the relay cannot turn into a signature
    for the wrong site.

    The RP ID must be the origin's effective domain or a registrable suffix of
    it, matched on label boundaries so `evil-example.com` cannot claim
    `example.com`.
    """
    if not rp_id:
        raise Sido3Error("Missing RP ID")
    if len(rp_id) > MAX_RP_ID_CHARS:
        raise Sido3Error("RP ID is too long")
    if rp_id != rp_id.strip() or any(c.isspace() for c in rp_id):
        raise Sido3Error("RP ID contains whitespace")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in rp_id):
        raise Sido3Error("RP ID contains control characters")

    rp_id = rp_id.lower()

    if rp_id in FORBIDDEN_RP_IDS:
        raise Sido3Error(f"'{rp_id}' is a public suffix and cannot be an RP ID")

    host = origin_effective_domain(origin)

    if rp_id == host:
        return rp_id

    # Suffix match on a label boundary. Without the leading dot,
    # "evil-example.com" would satisfy a check for "example.com".
    if host.endswith("." + rp_id):
        return rp_id

    raise Sido3Error(
        f"RP ID '{rp_id}' does not match origin host '{host}'"
    )


def _hex_field(value: str, name: str, expected_bytes: int = None) -> bytes:
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        raise Sido3Error(f"{name} is not valid hex")
    if expected_bytes is not None and len(decoded) != expected_bytes:
        raise Sido3Error(f"{name} must be {expected_bytes} bytes")
    return decoded


def _parse_query(payload: str, prefix: str) -> dict:
    if not payload.startswith(prefix):
        raise Sido3Error("Not a SIDO3 payload of the expected type")

    fields = {}
    for pair in payload[len(prefix):].split("&"):
        if not pair:
            continue
        key, _, value = pair.partition("=")
        if key in fields:
            raise Sido3Error(f"Duplicate field {key}")
        fields[key] = unquote(value)
    return fields


# ------------------------------------------------------------------ requests

def build_create_request(rp_id: str, origin: str, client_data_hash: bytes,
                         user_name: str = "", user_id: bytes = b"") -> str:
    """
    Registration request, built by the companion app.

    `origin` travels alongside `rp_id` so the signer can check them against each
    other and show the user the origin the browser actually reported.
    """
    validate_rp_id_for_origin(rp_id, origin)
    if len(client_data_hash) != 32:
        raise Sido3Error("clientDataHash must be 32 bytes")

    parts = [
        "rp=" + quote(rp_id, safe=""),
        "or=" + quote(origin, safe=""),
        "cdh=" + client_data_hash.hex(),
    ]
    if user_name:
        parts.append("un=" + quote(user_name[:MAX_USER_NAME_CHARS], safe=""))
    if user_id:
        parts.append("uid=" + user_id.hex())

    return CREATE_REQUEST_PREFIX + "&".join(parts)


def parse_create_request(payload: str) -> dict:
    fields = _parse_query(payload, CREATE_REQUEST_PREFIX)

    for required in ("rp", "or", "cdh"):
        if required not in fields:
            raise Sido3Error(f"Create request is missing '{required}'")

    rp_id = validate_rp_id_for_origin(fields["rp"], fields["or"])
    user_name = fields.get("un", "")
    if len(user_name) > MAX_USER_NAME_CHARS:
        raise Sido3Error("User name is too long")

    return {
        "operation": "create",
        "rp_id": rp_id,
        "origin": fields["or"],
        "client_data_hash": _hex_field(fields["cdh"], "clientDataHash", 32),
        "user_name": user_name,
        "user_id": _hex_field(fields["uid"], "user id") if "uid" in fields else b"",
    }


def build_get_request(rp_id: str, origin: str, client_data_hash: bytes,
                      credential_id: bytes) -> str:
    """Assertion request. The credential ID comes from the relying party."""
    validate_rp_id_for_origin(rp_id, origin)
    if len(client_data_hash) != 32:
        raise Sido3Error("clientDataHash must be 32 bytes")

    return GET_REQUEST_PREFIX + "&".join([
        "rp=" + quote(rp_id, safe=""),
        "or=" + quote(origin, safe=""),
        "cdh=" + client_data_hash.hex(),
        "cid=" + credential_id.hex(),
    ])


def parse_get_request(payload: str) -> dict:
    fields = _parse_query(payload, GET_REQUEST_PREFIX)

    for required in ("rp", "or", "cdh", "cid"):
        if required not in fields:
            raise Sido3Error(f"Get request is missing '{required}'")

    return {
        "operation": "get",
        "rp_id": validate_rp_id_for_origin(fields["rp"], fields["or"]),
        "origin": fields["or"],
        "client_data_hash": _hex_field(fields["cdh"], "clientDataHash", 32),
        "credential_id": _hex_field(fields["cid"], "credential id",
                                    CREDENTIAL_ID_BYTES),
    }


def parse_request(payload: str) -> dict:
    """Parse either kind, so a scanner does not need to know in advance."""
    if payload.startswith(CREATE_REQUEST_PREFIX):
        return parse_create_request(payload)
    if payload.startswith(GET_REQUEST_PREFIX):
        return parse_get_request(payload)
    raise Sido3Error("Not a SIDO3 request")


# ------------------------------------------------------------------ responses

def build_create_response(authenticator_data_bytes: bytes, signature: bytes) -> str:
    """
    Registration response.

    The credential ID and the public key are both already inside
    authenticatorData, so nothing is repeated: the companion app parses them out
    when assembling the WebAuthn JSON.
    """
    return CREATE_RESPONSE_PREFIX + "&".join([
        "ad=" + authenticator_data_bytes.hex(),
        "sig=" + signature.hex(),
    ])


def build_get_response(authenticator_data_bytes: bytes, signature: bytes,
                       credential_id: bytes) -> str:
    return GET_RESPONSE_PREFIX + "&".join([
        "ad=" + authenticator_data_bytes.hex(),
        "sig=" + signature.hex(),
        "cid=" + credential_id.hex(),
    ])


def parse_create_response(payload: str) -> dict:
    fields = _parse_query(payload, CREATE_RESPONSE_PREFIX)
    for required in ("ad", "sig"):
        if required not in fields:
            raise Sido3Error(f"Create response is missing '{required}'")
    return {
        "authenticator_data": _hex_field(fields["ad"], "authenticatorData"),
        "signature": _hex_field(fields["sig"], "signature"),
    }


def parse_get_response(payload: str) -> dict:
    fields = _parse_query(payload, GET_RESPONSE_PREFIX)
    for required in ("ad", "sig", "cid"):
        if required not in fields:
            raise Sido3Error(f"Get response is missing '{required}'")
    return {
        "authenticator_data": _hex_field(fields["ad"], "authenticatorData"),
        "signature": _hex_field(fields["sig"], "signature"),
        "credential_id": _hex_field(fields["cid"], "credential id",
                                    CREDENTIAL_ID_BYTES),
    }


# ------------------------------------------------------------------ signing

def sign_request(seed_bytes: bytes, request: dict, nonce: bytes = None) -> str:
    """
    Produce the response QR for a parsed request.

    Deliberately takes an already-parsed request: parsing and signing are
    separate so a view can show the user what was scanned, wait for approval,
    and only then call this.
    """
    if request["operation"] == "create":
        import os

        credential = Credential(
            seed_bytes, request["rp_id"], nonce or os.urandom(NONCE_BYTES),
        )
        auth_data = authenticator_data(
            credential.rp_hash, user_present=True, credential=credential,
        )
        signature = credential.sign(auth_data + request["client_data_hash"])
        return build_create_response(auth_data, signature)

    if request["operation"] == "get":
        try:
            credential = Credential.from_credential_id(
                seed_bytes, request["rp_id"], request["credential_id"],
            )
        except CredentialError:
            raise Sido3Error("This credential was not issued by this seed")

        auth_data = authenticator_data(credential.rp_hash, user_present=True)
        signature = credential.sign(auth_data + request["client_data_hash"])
        return build_get_response(auth_data, signature, credential.credential_id)

    raise Sido3Error(f"Unknown operation {request['operation']}")


def client_data_hash_for(challenge_b64url: str, origin: str,
                         operation: str) -> bytes:
    """
    Build clientDataJSON and hash it, the way the companion app must.

    Provided here so the format has one definition rather than two that can
    drift, and so the tests can check a signature the way a relying party would.
    """
    kind = "webauthn.create" if operation == "create" else "webauthn.get"
    client_data = (
        '{"type":"' + kind + '",'
        '"challenge":"' + challenge_b64url + '",'
        '"origin":"' + origin + '",'
        '"crossOrigin":false}'
    )
    return hashlib.sha256(client_data.encode("utf-8")).digest()
