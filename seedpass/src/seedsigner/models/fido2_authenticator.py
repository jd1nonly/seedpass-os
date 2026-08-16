"""
CTAP2 authenticator: getInfo, makeCredential, getAssertion.

The three commands a relying party needs for registration and login. Everything
else CTAP2 defines -- PIN protocols, credential management, bio enrolment,
large blobs -- is deliberately absent. Each would be more attacker-reachable
code, and none is needed by a device whose credentials are derived rather than
stored and whose user verification is a button on the front.

User presence is not optional here
----------------------------------
Every makeCredential and getAssertion calls `confirm` before a key is touched.
That callback is expected to put the RP ID on the screen and wait for a physical
button press. Without it a host with USB access could silently mint credentials
and sign assertions for any site it named -- the device would become a signing
oracle that happens to be plugged in. The press is the only thing that makes a
signature evidence of a human decision.

What the device cannot check
----------------------------
The RP ID arrives from the host, and CTAP has no way to verify it. On a real
browser it is derived from the page origin and is trustworthy; a malicious
*application* on the same machine can claim to be any site. This is inherent to
CTAP rather than specific to this implementation -- a YubiKey has the same
property -- and it is why the RP ID is shown to the user before signing.
"""
import hashlib
import os

from seedsigner.models import fido2_cbor as cbor
from seedsigner.models.fido2_credential import (
    AAGUID,
    NONCE_BYTES,
    Credential,
    CredentialError,
    authenticator_data,
    rp_id_hash,
)


# CTAP2 command codes
CMD_MAKE_CREDENTIAL = 0x01
CMD_GET_ASSERTION = 0x02
CMD_GET_INFO = 0x04
CMD_CLIENT_PIN = 0x06
CMD_RESET = 0x07
CMD_GET_NEXT_ASSERTION = 0x08

# CTAP2 status codes
CTAP2_OK = 0x00
CTAP1_ERR_INVALID_PARAMETER = 0x02
CTAP2_ERR_CBOR_UNEXPECTED_TYPE = 0x11
CTAP2_ERR_INVALID_CBOR = 0x12
CTAP2_ERR_MISSING_PARAMETER = 0x14
CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26
CTAP2_ERR_OPERATION_DENIED = 0x27
CTAP2_ERR_UNSUPPORTED_OPTION = 0x2B
CTAP2_ERR_INVALID_OPTION = 0x2C
CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D
CTAP2_ERR_NO_CREDENTIALS = 0x2E
CTAP2_ERR_PIN_NOT_SET = 0x35
CTAP2_ERR_UNSUPPORTED_EXTENSION = 0x2F
CTAP1_ERR_INVALID_COMMAND = 0x01

# COSE algorithm identifiers
ALG_ES256 = -7

# Bounds on host-supplied strings, so a display cannot be flooded and a buffer
# cannot be grown by a hostile name.
MAX_RP_ID_CHARS = 253          # a DNS name cannot exceed this
MAX_NAME_CHARS = 64
MAX_ALLOW_LIST = 16


class Ctap2Error(Exception):
    """Carries a CTAP2 status code to return to the host."""

    def __init__(self, code: int, message: str = ""):
        super().__init__(message or f"CTAP2 error 0x{code:02x}")
        self.code = code


def _require(condition: bool, code: int, message: str = "") -> None:
    if not condition:
        raise Ctap2Error(code, message)


def _text(value, limit: int, code: int = CTAP2_ERR_CBOR_UNEXPECTED_TYPE) -> str:
    _require(isinstance(value, str), code, "Expected a text string")
    _require(len(value) <= limit, CTAP1_ERR_INVALID_PARAMETER, "String too long")
    return value


class Authenticator:
    """
    A stateless CTAP2 authenticator.

    `confirm(rp_id, action)` must block until the user physically approves, and
    return False if they decline or it times out.
    """

    def __init__(self, seed_bytes: bytes, confirm=None):
        self.seed_bytes = seed_bytes
        self.confirm = confirm or (lambda rp_id, action: False)

    # ------------------------------------------------------------------ dispatch

    def handle(self, message: bytes) -> bytes:
        """
        Process one CTAP2 message, returning status byte + optional CBOR body.

        Never raises: a host must get a status code back rather than a hung
        transaction, and an unexpected exception here would otherwise be
        indistinguishable from the device dying.
        """
        if not message:
            return bytes([CTAP1_ERR_INVALID_PARAMETER])

        command = message[0]
        body = message[1:]

        try:
            if command == CMD_GET_INFO:
                response = self.get_info()
            elif command == CMD_MAKE_CREDENTIAL:
                response = self.make_credential(self._parse(body))
            elif command == CMD_GET_ASSERTION:
                response = self.get_assertion(self._parse(body))
            elif command in (CMD_CLIENT_PIN, CMD_RESET, CMD_GET_NEXT_ASSERTION):
                # Not implemented, and saying so is better than silence. Reset in
                # particular has no meaning: there is nothing stored to erase,
                # and honouring it would imply the seed could be wiped by a host.
                raise Ctap2Error(CTAP1_ERR_INVALID_COMMAND)
            else:
                raise Ctap2Error(CTAP1_ERR_INVALID_COMMAND)

        except Ctap2Error as e:
            return bytes([e.code])
        except cbor.CborError:
            return bytes([CTAP2_ERR_INVALID_CBOR])
        except CredentialError:
            # A credential ID that is not ours. Reported as "no credentials"
            # rather than something more specific, so a host cannot use the
            # error to distinguish a forged ID from an unknown one.
            return bytes([CTAP2_ERR_NO_CREDENTIALS])
        except Exception:
            return bytes([CTAP2_ERR_OPERATION_DENIED])

        if response is None:
            return bytes([CTAP2_OK])
        return bytes([CTAP2_OK]) + cbor.encode(response)

    @staticmethod
    def _parse(body: bytes) -> dict:
        if not body:
            return {}
        parameters = cbor.decode(body)
        _require(isinstance(parameters, dict), CTAP2_ERR_INVALID_CBOR)
        return parameters

    # ------------------------------------------------------------------ getInfo

    def get_info(self) -> dict:
        """
        Capabilities. Deliberately spare.

        `rk: False` says discoverable (resident) credentials are not supported,
        which is true and is what makes statelessness possible -- the RP keeps
        the credential ID and hands it back. `uv: False` says no on-device user
        verification beyond presence; there is no PIN and no biometric.
        """
        return {
            1: ["FIDO_2_0"],            # versions
            2: [],                      # extensions: none
            3: AAGUID,
            4: {                        # options
                "plat": False,          # roaming, not platform-bound
                "rk": False,            # no discoverable credentials
                "up": True,             # user presence supported
                "uv": False,            # no on-device user verification
            },
            5: 7609,                    # maxMsgSize
            9: ["usb"],                 # transports
            10: [{"alg": ALG_ES256, "type": "public-key"}],
        }

    # ------------------------------------------------------------ makeCredential

    def make_credential(self, parameters: dict) -> dict:
        client_data_hash = parameters.get(1)
        rp = parameters.get(2)
        user = parameters.get(3)
        algorithms = parameters.get(4)
        options = parameters.get(7) or {}

        _require(isinstance(client_data_hash, (bytes, bytearray)),
                 CTAP2_ERR_MISSING_PARAMETER, "clientDataHash")
        _require(len(client_data_hash) == 32,
                 CTAP1_ERR_INVALID_PARAMETER, "clientDataHash must be 32 bytes")
        _require(isinstance(rp, dict), CTAP2_ERR_MISSING_PARAMETER, "rp")
        _require(isinstance(user, dict), CTAP2_ERR_MISSING_PARAMETER, "user")
        _require(isinstance(algorithms, list), CTAP2_ERR_MISSING_PARAMETER, "pubKeyCredParams")

        rp_id = _text(rp.get("id"), MAX_RP_ID_CHARS, CTAP2_ERR_MISSING_PARAMETER)

        # Only ES256. An RP asking solely for RS256 gets a clear refusal rather
        # than a credential it cannot verify.
        _require(
            any(
                isinstance(entry, dict) and entry.get("alg") == ALG_ES256
                for entry in algorithms
            ),
            CTAP2_ERR_UNSUPPORTED_ALGORITHM,
        )

        # Discoverable credentials would need storage, and this device has none.
        if options.get("rk"):
            raise Ctap2Error(CTAP2_ERR_UNSUPPORTED_OPTION, "Resident keys not supported")
        if options.get("uv"):
            raise Ctap2Error(CTAP2_ERR_UNSUPPORTED_OPTION, "No user verification")

        # The physical button. Before any key exists.
        _require(self.confirm(rp_id, "register"), CTAP2_ERR_OPERATION_DENIED)

        credential = Credential(self.seed_bytes, rp_id, os.urandom(NONCE_BYTES))

        auth_data = authenticator_data(
            credential.rp_hash, user_present=True, credential=credential,
        )
        signature = credential.sign(auth_data + bytes(client_data_hash))

        return {
            1: "packed",
            2: auth_data,
            3: {"alg": ALG_ES256, "sig": signature},
        }

    # -------------------------------------------------------------- getAssertion

    def get_assertion(self, parameters: dict) -> dict:
        rp_id = _text(parameters.get(1), MAX_RP_ID_CHARS, CTAP2_ERR_MISSING_PARAMETER)
        client_data_hash = parameters.get(2)
        allow_list = parameters.get(3)
        options = parameters.get(5) or {}

        _require(isinstance(client_data_hash, (bytes, bytearray)),
                 CTAP2_ERR_MISSING_PARAMETER, "clientDataHash")
        _require(len(client_data_hash) == 32,
                 CTAP1_ERR_INVALID_PARAMETER, "clientDataHash must be 32 bytes")

        # Without an allowList there is nothing to derive from: this device has
        # no discoverable credentials to search.
        _require(isinstance(allow_list, list) and allow_list,
                 CTAP2_ERR_NO_CREDENTIALS, "allowList required")
        _require(len(allow_list) <= MAX_ALLOW_LIST,
                 CTAP1_ERR_INVALID_PARAMETER, "allowList too long")

        if options.get("uv"):
            raise Ctap2Error(CTAP2_ERR_UNSUPPORTED_OPTION, "No user verification")

        credential = self._find_credential(rp_id, allow_list)
        _require(credential is not None, CTAP2_ERR_NO_CREDENTIALS)

        _require(self.confirm(rp_id, "sign in"), CTAP2_ERR_OPERATION_DENIED)

        auth_data = authenticator_data(credential.rp_hash, user_present=True)
        signature = credential.sign(auth_data + bytes(client_data_hash))

        return {
            1: {"type": "public-key", "id": credential.credential_id},
            2: auth_data,
            3: signature,
        }

    def _find_credential(self, rp_id: str, allow_list: list):
        """
        The first credential in the allowList this device actually issued.

        Every candidate is checked before the user is prompted, so a decline
        does not leak which entry was recognised.
        """
        for entry in allow_list:
            if not isinstance(entry, dict):
                continue
            if entry.get("type") != "public-key":
                continue

            credential_id = entry.get("id")
            if not isinstance(credential_id, (bytes, bytearray)):
                continue

            try:
                return Credential.from_credential_id(
                    self.seed_bytes, rp_id, bytes(credential_id),
                )
            except CredentialError:
                continue

        return None
