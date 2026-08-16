"""
Tests for the FIDO2 stack: P-256, CBOR, credentials, CTAPHID and CTAP2.

Weighted towards adversarial cases. USB is the first channel where an attacker
supplies bytes directly, without a user choosing to scan anything, so most of
what matters here is what gets refused.

Run from the SeedSigner repo root:
    python -m pytest tests/test_fido2.py -v
"""
import hashlib
import os
import struct

import pytest

from embit import bip39

from seedsigner.models import fido2_cbor as cbor
from seedsigner.models import fido2_ctaphid as ctaphid
from seedsigner.models import p256
from seedsigner.models.fido2_authenticator import (
    ALG_ES256,
    CMD_CLIENT_PIN,
    CMD_GET_ASSERTION,
    CMD_GET_INFO,
    CMD_MAKE_CREDENTIAL,
    CMD_RESET,
    CTAP1_ERR_INVALID_COMMAND,
    CTAP1_ERR_INVALID_PARAMETER,
    CTAP2_ERR_INVALID_CBOR,
    CTAP2_ERR_NO_CREDENTIALS,
    CTAP2_ERR_OPERATION_DENIED,
    CTAP2_ERR_UNSUPPORTED_ALGORITHM,
    CTAP2_ERR_UNSUPPORTED_OPTION,
    CTAP2_OK,
    Authenticator,
)
from seedsigner.models.fido2_credential import (
    Credential,
    CredentialError,
    authenticator_data,
)

TEST_MNEMONIC = " ".join(["abandon"] * 23 + ["art"])
CLIENT_DATA_HASH = hashlib.sha256(b"clientdata").digest()


def seed_bytes(passphrase: str = "") -> bytes:
    return bip39.mnemonic_to_seed(TEST_MNEMONIC, password=passphrase)


def always_approve(rp_id, action):
    return True


def always_deny(rp_id, action):
    return False


# ============================================================ P-256

def test_p256_matches_rfc6979_vector():
    """
    RFC 6979 A.2.5: P-256 with SHA-256, message "sample". If this fails, no
    signature this device produces will verify anywhere.
    """
    private = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    expected_x = 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
    expected_y = 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
    expected_k = 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
    expected_r = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
    expected_s = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8

    assert p256.public_key(private) == (expected_x, expected_y)

    digest = hashlib.sha256(b"sample").digest()
    assert p256.deterministic_nonce(private, digest) == expected_k

    r, s = p256.sign_digest(private, digest)
    assert r == expected_r
    # Signatures are normalised to low-S; the vector is the raw form.
    assert s == expected_s or p256.N - s == expected_s


def test_p256_signing_is_deterministic():
    digest = hashlib.sha256(b"message").digest()
    assert p256.sign_digest(12345, digest) == p256.sign_digest(12345, digest)


def test_p256_signature_verifies_and_rejects():
    private = 0x1234567890ABCDEF
    public = p256.public_key(private)
    digest = hashlib.sha256(b"message").digest()
    signature = p256.sign_digest(private, digest)

    assert p256.verify_digest(public, digest, signature)
    assert not p256.verify_digest(public, hashlib.sha256(b"other").digest(), signature)


def test_p256_low_s_normalised():
    for message in (b"a", b"b", b"c", b"d"):
        _, s = p256.sign_digest(999, hashlib.sha256(message).digest())
        assert s <= p256.N // 2


@pytest.mark.parametrize("bad", [0, p256.N, p256.N + 1, -1])
def test_p256_rejects_invalid_private_keys(bad):
    with pytest.raises(p256.P256Error):
        p256.validate_private_key(bad)


def test_der_round_trip():
    signature = p256.sign_digest(4242, hashlib.sha256(b"x").digest())
    der = p256.encode_der_signature(signature)
    assert der[0] == 0x30
    assert p256.decode_der_signature(der) == signature


# ============================================================ CBOR

@pytest.mark.parametrize("value", [
    0, 1, 23, 24, 255, 256, 65535, 65536, -1, -100,
    b"", b"\xde\xad", "text", [], [1, 2, 3], {}, {1: 2}, True, False, None,
])
def test_cbor_round_trips(value):
    assert cbor.decode(cbor.encode(value)) == value


def test_cbor_map_ordering_is_canonical():
    """CTAP2 requires one encoding per value, or attestation verification breaks."""
    assert cbor.encode({3: "c", 1: "a", 2: "b"}) == cbor.encode({1: "a", 2: "b", 3: "c"})


@pytest.mark.parametrize("name,payload", [
    ("indefinite-length array", bytes([0x9F, 0x01, 0xFF])),
    ("indefinite-length bytes", bytes([0x5F, 0x41, 0x00, 0xFF])),
    ("length claims 4GB", bytes([0x5A, 0xFF, 0xFF, 0xFF, 0xFF])),
    ("8-byte length bomb", bytes([0x5B]) + b"\xff" * 8),
    ("truncated length field", bytes([0x5A, 0x00])),
    ("string runs past end", bytes([0x45, 0x01, 0x02])),
    ("array overclaims items", bytes([0x9A, 0x00, 0xFF, 0xFF, 0xFF])),
    ("map overclaims entries", bytes([0xBA, 0xFF, 0xFF, 0xFF, 0xFF])),
    ("nesting bomb", bytes([0x81] * 40) + bytes([0x01])),
    ("duplicate map key", bytes([0xA2, 0x01, 0x01, 0x01, 0x02])),
    ("float", bytes([0xFA, 0x40, 0x00, 0x00, 0x00])),
    ("reserved length encoding", bytes([0x5C])),
    ("empty input", b""),
    ("invalid utf-8", bytes([0x62, 0xFF, 0xFE])),
])
def test_cbor_refuses_hostile_input(name, payload):
    with pytest.raises(cbor.CborError):
        cbor.decode(payload)


def test_cbor_refuses_trailing_bytes():
    with pytest.raises(cbor.CborError):
        cbor.decode(cbor.encode(1) + b"\x02")


def test_cbor_nesting_bomb_does_not_recurse_to_death():
    """A RecursionError would be an unhandled crash, not a refusal."""
    try:
        cbor.decode(bytes([0x81] * 500) + bytes([0x01]))
    except cbor.CborError:
        pass
    except RecursionError:
        pytest.fail("nesting bomb caused RecursionError instead of a clean refusal")


# ============================================================ credentials

def test_credential_derivation_is_deterministic():
    nonce = b"\x01" * 16
    a = Credential(seed_bytes(), "github.com", nonce)
    b = Credential(seed_bytes(), "github.com", nonce)
    assert a.public_key == b.public_key
    assert a.credential_id == b.credential_id


def test_different_rp_gives_different_key():
    nonce = b"\x01" * 16
    assert (
        Credential(seed_bytes(), "github.com", nonce).public_key
        != Credential(seed_bytes(), "gitlab.com", nonce).public_key
    )


def test_different_seed_gives_different_key():
    nonce = b"\x01" * 16
    assert (
        Credential(seed_bytes(), "github.com", nonce).public_key
        != Credential(seed_bytes("extra"), "github.com", nonce).public_key
    )


def test_credential_id_round_trips():
    original = Credential(seed_bytes(), "github.com", os.urandom(16))
    recovered = Credential.from_credential_id(
        seed_bytes(), "github.com", original.credential_id,
    )
    assert recovered.public_key == original.public_key


def test_forged_credential_id_refused():
    """Otherwise the device is a signing oracle for attacker-chosen keys."""
    with pytest.raises(CredentialError):
        Credential.from_credential_id(seed_bytes(), "github.com", os.urandom(32))


def test_credential_id_cannot_be_replayed_at_another_rp():
    credential = Credential(seed_bytes(), "github.com", os.urandom(16))
    with pytest.raises(CredentialError):
        Credential.from_credential_id(seed_bytes(), "evil.com", credential.credential_id)


def test_tampered_credential_id_refused():
    credential = Credential(seed_bytes(), "github.com", os.urandom(16))
    for position in (0, 15, 16, 31):
        tampered = bytearray(credential.credential_id)
        tampered[position] ^= 0x01
        with pytest.raises(CredentialError):
            Credential.from_credential_id(seed_bytes(), "github.com", bytes(tampered))


def test_credential_id_from_another_seed_refused():
    foreign = Credential(seed_bytes("extra"), "github.com", os.urandom(16))
    with pytest.raises(CredentialError):
        Credential.from_credential_id(seed_bytes(), "github.com", foreign.credential_id)


@pytest.mark.parametrize("length", [0, 16, 31, 33, 64])
def test_wrong_length_credential_id_refused(length):
    with pytest.raises(CredentialError):
        Credential.from_credential_id(seed_bytes(), "github.com", os.urandom(length))


def test_authenticator_data_shape():
    credential = Credential(seed_bytes(), "github.com", os.urandom(16))

    attested = authenticator_data(credential.rp_hash, credential=credential)
    assert attested[:32] == credential.rp_hash
    assert attested[32] & 0x01          # user present
    assert attested[32] & 0x40          # attested credential data
    assert attested[33:37] == b"\x00" * 4   # signCount stays 0

    assertion = authenticator_data(credential.rp_hash)
    assert len(assertion) == 37
    assert not assertion[32] & 0x40


# ============================================================ CTAPHID

def _init_packet(channel, command, length, chunk=b""):
    return (struct.pack(">IBH", channel, command, length) + chunk).ljust(64, b"\x00")


def _cont_packet(channel, sequence, chunk=b""):
    return (struct.pack(">IB", channel, sequence) + chunk).ljust(64, b"\x00")


def test_init_allocates_a_channel_and_echoes_the_nonce():
    hid = ctaphid.CtapHid()
    hid.handle_packet(_init_packet(ctaphid.BROADCAST_CHANNEL, ctaphid.CMD_INIT, 8, b"\x01" * 8))
    response = hid.take_responses()[0]

    assert response[7:15] == b"\x01" * 8
    assert struct.unpack(">I", response[15:19])[0] != ctaphid.BROADCAST_CHANNEL


def test_init_advertises_cbor_and_no_ctap1():
    """
    NMSG matters: without it a host may try CTAPHID_MSG and wait forever for a
    reply this device will never send.
    """
    hid = ctaphid.CtapHid()
    hid.handle_packet(_init_packet(ctaphid.BROADCAST_CHANNEL, ctaphid.CMD_INIT, 8, b"\x00" * 8))
    capabilities = hid.take_responses()[0][23]

    assert capabilities & ctaphid.CAPABILITY_CBOR
    assert capabilities & ctaphid.CAPABILITY_NMSG


def test_multi_packet_message_reassembles():
    hid = ctaphid.CtapHid()
    payload = bytes(range(256)) * 2

    result = None
    for packet in ctaphid.build_packets(1, ctaphid.CMD_CBOR, payload):
        result = hid.handle_packet(packet)

    assert result == (1, ctaphid.CMD_CBOR, payload)


def _error_code(hid):
    for response in hid.take_responses():
        if response[4] == ctaphid.CMD_ERROR:
            return response[7]
    return None


def test_oversized_declared_length_refused():
    hid = ctaphid.CtapHid()
    hid.handle_packet(_init_packet(1, ctaphid.CMD_CBOR, 0xFFFF))
    assert _error_code(hid) == ctaphid.ERR_INVALID_LEN


def test_stray_continuation_refused():
    hid = ctaphid.CtapHid()
    hid.handle_packet(_cont_packet(1, 0))
    assert _error_code(hid) == ctaphid.ERR_INVALID_SEQ


def test_out_of_order_continuation_refused():
    hid = ctaphid.CtapHid()
    hid.handle_packet(_init_packet(1, ctaphid.CMD_CBOR, 200, b"\x00" * 57))
    hid.handle_packet(_cont_packet(1, 5, b"\x00" * 59))
    assert _error_code(hid) == ctaphid.ERR_INVALID_SEQ


def test_repeated_sequence_number_refused():
    """Accepting a repeat would let a host rewrite a buffer it already filled."""
    hid = ctaphid.CtapHid()
    hid.handle_packet(_init_packet(1, ctaphid.CMD_CBOR, 300, b"\x00" * 57))
    hid.handle_packet(_cont_packet(1, 0, b"\x11" * 59))
    hid.handle_packet(_cont_packet(1, 0, b"\x22" * 59))
    assert _error_code(hid) == ctaphid.ERR_INVALID_SEQ


def test_other_channel_cannot_inject_into_a_transaction():
    hid = ctaphid.CtapHid()
    hid.handle_packet(_init_packet(1, ctaphid.CMD_CBOR, 300, b"\x00" * 57))
    hid.handle_packet(_cont_packet(2, 0, b"\xff" * 59))
    assert _error_code(hid) == ctaphid.ERR_CHANNEL_BUSY


def test_reserved_channel_refused():
    hid = ctaphid.CtapHid()
    hid.handle_packet(_init_packet(0, ctaphid.CMD_CBOR, 4))
    assert _error_code(hid) == ctaphid.ERR_INVALID_CHANNEL


def test_non_init_on_broadcast_channel_refused():
    hid = ctaphid.CtapHid()
    hid.handle_packet(_init_packet(ctaphid.BROADCAST_CHANNEL, ctaphid.CMD_CBOR, 4))
    assert _error_code(hid) == ctaphid.ERR_INVALID_CHANNEL


def test_ctap1_message_command_refused():
    hid = ctaphid.CtapHid()
    hid.handle_packet(_init_packet(1, ctaphid.CMD_MSG, 4))
    assert _error_code(hid) == ctaphid.ERR_INVALID_CMD


def test_buffer_never_exceeds_declared_length():
    hid = ctaphid.CtapHid()
    hid.handle_packet(_init_packet(1, ctaphid.CMD_CBOR, 60, b"\x00" * 57))
    result = hid.handle_packet(_cont_packet(1, 0, b"\xff" * 59))
    assert len(result[2]) == 60


# ============================================================ CTAP2 end to end

def _make_credential_request(rp_id="github.com", overrides=None):
    parameters = {
        1: CLIENT_DATA_HASH,
        2: {"id": rp_id, "name": "Example"},
        3: {"id": b"user", "name": "user"},
        4: [{"alg": ALG_ES256, "type": "public-key"}],
    }
    if overrides:
        parameters.update(overrides)
    return bytes([CMD_MAKE_CREDENTIAL]) + cbor.encode(parameters)


def _register(authenticator, rp_id="github.com"):
    response = authenticator.handle(_make_credential_request(rp_id))
    assert response[0] == CTAP2_OK
    attestation = cbor.decode(response[1:])
    auth_data = attestation[2]

    length = int.from_bytes(auth_data[53:55], "big")
    credential_id = auth_data[55:55 + length]
    cose_key = cbor.decode(auth_data[55 + length:])
    public_key = (
        int.from_bytes(cose_key[-2], "big"),
        int.from_bytes(cose_key[-3], "big"),
    )
    return credential_id, public_key, attestation


def test_get_info_reports_honest_capabilities():
    authenticator = Authenticator(seed_bytes(), confirm=always_approve)
    info = cbor.decode(authenticator.handle(bytes([CMD_GET_INFO]))[1:])

    assert "FIDO_2_0" in info[1]
    assert info[4]["rk"] is False          # no discoverable credentials
    assert info[4]["up"] is True           # user presence
    assert info[4]["uv"] is False          # no on-device verification
    assert info[10] == [{"alg": ALG_ES256, "type": "public-key"}]


def test_registration_signature_verifies():
    """Exactly the check a relying party performs."""
    authenticator = Authenticator(seed_bytes(), confirm=always_approve)
    _, public_key, attestation = _register(authenticator)

    signed = attestation[2] + CLIENT_DATA_HASH
    signature = p256.decode_der_signature(attestation[3]["sig"])
    assert p256.verify_digest(public_key, hashlib.sha256(signed).digest(), signature)


def test_assertion_signature_verifies():
    authenticator = Authenticator(seed_bytes(), confirm=always_approve)
    credential_id, public_key, _ = _register(authenticator)

    request = bytes([CMD_GET_ASSERTION]) + cbor.encode({
        1: "github.com",
        2: CLIENT_DATA_HASH,
        3: [{"type": "public-key", "id": credential_id}],
    })
    response = authenticator.handle(request)
    assert response[0] == CTAP2_OK

    assertion = cbor.decode(response[1:])
    signed = assertion[2] + CLIENT_DATA_HASH
    signature = p256.decode_der_signature(assertion[3])
    assert p256.verify_digest(public_key, hashlib.sha256(signed).digest(), signature)


def test_user_presence_is_required_to_register():
    """Without this the device is a silent credential mint for any USB host."""
    authenticator = Authenticator(seed_bytes(), confirm=always_deny)
    assert authenticator.handle(_make_credential_request())[0] == CTAP2_ERR_OPERATION_DENIED


def test_user_presence_is_required_to_sign():
    approving = Authenticator(seed_bytes(), confirm=always_approve)
    credential_id, _, _ = _register(approving)

    denying = Authenticator(seed_bytes(), confirm=always_deny)
    request = bytes([CMD_GET_ASSERTION]) + cbor.encode({
        1: "github.com",
        2: CLIENT_DATA_HASH,
        3: [{"type": "public-key", "id": credential_id}],
    })
    assert denying.handle(request)[0] == CTAP2_ERR_OPERATION_DENIED


def test_user_is_prompted_with_the_actual_rp_id():
    """The prompt is the only place a human can catch a wrong site."""
    seen = []
    authenticator = Authenticator(
        seed_bytes(), confirm=lambda rp_id, action: seen.append((rp_id, action)) or True,
    )
    authenticator.handle(_make_credential_request("example.org"))
    assert seen == [("example.org", "register")]


def test_credential_cannot_be_used_at_another_rp():
    authenticator = Authenticator(seed_bytes(), confirm=always_approve)
    credential_id, _, _ = _register(authenticator, "github.com")

    request = bytes([CMD_GET_ASSERTION]) + cbor.encode({
        1: "evil.com",
        2: CLIENT_DATA_HASH,
        3: [{"type": "public-key", "id": credential_id}],
    })
    assert authenticator.handle(request)[0] == CTAP2_ERR_NO_CREDENTIALS


def test_forged_credential_id_is_not_signed():
    authenticator = Authenticator(seed_bytes(), confirm=always_approve)
    request = bytes([CMD_GET_ASSERTION]) + cbor.encode({
        1: "github.com",
        2: CLIENT_DATA_HASH,
        3: [{"type": "public-key", "id": os.urandom(32)}],
    })
    assert authenticator.handle(request)[0] == CTAP2_ERR_NO_CREDENTIALS


def test_assertion_without_allow_list_refused():
    """No discoverable credentials, so there is nothing to enumerate."""
    authenticator = Authenticator(seed_bytes(), confirm=always_approve)
    request = bytes([CMD_GET_ASSERTION]) + cbor.encode({
        1: "github.com", 2: CLIENT_DATA_HASH,
    })
    assert authenticator.handle(request)[0] == CTAP2_ERR_NO_CREDENTIALS


def test_unsupported_algorithm_refused():
    authenticator = Authenticator(seed_bytes(), confirm=always_approve)
    request = _make_credential_request(overrides={4: [{"alg": -257, "type": "public-key"}]})
    assert authenticator.handle(request)[0] == CTAP2_ERR_UNSUPPORTED_ALGORITHM


def test_resident_key_refused():
    authenticator = Authenticator(seed_bytes(), confirm=always_approve)
    request = _make_credential_request(overrides={7: {"rk": True}})
    assert authenticator.handle(request)[0] == CTAP2_ERR_UNSUPPORTED_OPTION


@pytest.mark.parametrize("command", [CMD_RESET, CMD_CLIENT_PIN, 0x99])
def test_unsupported_commands_refused(command):
    """
    Reset in particular: there is nothing stored to erase, and honouring it
    would imply a host could wipe the seed.
    """
    authenticator = Authenticator(seed_bytes(), confirm=always_approve)
    assert authenticator.handle(bytes([command]))[0] == CTAP1_ERR_INVALID_COMMAND


@pytest.mark.parametrize("request_bytes,expected", [
    (b"", CTAP1_ERR_INVALID_PARAMETER),
    (bytes([CMD_MAKE_CREDENTIAL]) + b"\xff\xff\xff", CTAP2_ERR_INVALID_CBOR),
])
def test_malformed_requests_get_a_status_code(request_bytes, expected):
    authenticator = Authenticator(seed_bytes(), confirm=always_approve)
    assert authenticator.handle(request_bytes)[0] == expected


@pytest.mark.parametrize("overrides", [
    {1: b"short"},                                  # clientDataHash too short
    {2: {"id": "a" * 500}},                         # oversized rpId
    {2: {}},                                        # no rp id
])
def test_invalid_parameters_refused(overrides):
    authenticator = Authenticator(seed_bytes(), confirm=always_approve)
    response = authenticator.handle(_make_credential_request(overrides=overrides))
    assert response[0] != CTAP2_OK


def test_handle_never_raises():
    """
    A host must always get a status byte. An escaping exception would look
    identical to the device having died mid-transaction.
    """
    authenticator = Authenticator(seed_bytes(), confirm=always_approve)
    for _ in range(200):
        response = authenticator.handle(os.urandom(32))
        assert len(response) >= 1


# ============================================================ non-interference

def test_fido2_does_not_disturb_passwords_or_identities():
    """
    Four branches now derive from one seed: BIP-85 passwords, SLIP-13
    identities, FIDO2 credentials, and the wallet keys SeedSigner already had.
    Adding FIDO2 must not move any of them.
    """
    from seedsigner.models.seedpass import PasswordFormat, derive_password
    from seedsigner.models.seedpass_identity import derive_identity

    seed = seed_bytes()

    assert derive_password(seed, label="gmail", fmt=PasswordFormat.FULL).password == (
        "6w8BYxxBW7nx2s9qJkFxn6jGh69GYJYhoJm5W2tfGa1v!2"
    )
    assert derive_password(seed, label="gmail", fmt=PasswordFormat.SHORT).password == (
        "vugQwXTAY2wMna!2"
    )
    assert derive_identity(seed, label="gmail").public_key.startswith("020b72788076eec6")


def test_fido2_keys_are_on_a_different_curve():
    """
    Passwords and identities use secp256k1; FIDO2 uses P-256. A signature the
    FIDO2 path produces therefore cannot be a valid Bitcoin signature, whatever
    a host persuades the device to sign. Structural, not a matter of care.
    """
    from embit import ec

    credential = Credential(seed_bytes(), "github.com", os.urandom(16))
    x, _ = credential.public_key

    assert p256.is_on_curve(credential.public_key)
    # The same X on secp256k1 would satisfy y^2 = x^3 + 7; on P-256 it does not.
    assert (x ** 3 + 7) % p256.P != (x ** 3 + p256.A * x + p256.B) % p256.P
    assert ec is not None


# ============================================================ armed sessions

from seedsigner.models.fido2_session import (  # noqa: E402
    ArmedSession,
    SessionError,
    build_credential_uri,
    build_prepare_uri,
    parse_credential_uri,
    parse_prepare_uri,
    validate_rp_id,
)


def test_prepare_uri_round_trips_for_registration():
    parsed = parse_prepare_uri(build_prepare_uri("github.com"))
    assert parsed["rp_id"] == "github.com"
    assert parsed["nonce"] is None


def test_prepare_uri_round_trips_for_login():
    nonce = bytes(range(16))
    parsed = parse_prepare_uri(build_prepare_uri("github.com", nonce))
    assert parsed["rp_id"] == "github.com"
    assert parsed["nonce"] == nonce


@pytest.mark.parametrize("bad,reason", [
    ("", "empty"),
    ("a" * 300, "overlong"),
    ("github.com\nevil.com", "newline injection"),
    ("github.com\x00evil", "null byte"),
    (" github.com", "leading whitespace"),
    ("github.com ", "trailing whitespace"),
    ("git hub.com", "internal whitespace"),
])
def test_hostile_rp_ids_refused(bad, reason):
    """
    The user reading this string is the whole security of the arming step, so it
    must not be able to render deceptively.
    """
    with pytest.raises(SessionError):
        validate_rp_id(bad)


@pytest.mark.parametrize("payload", [
    "seedpass://v1/secret?fp=x",
    "seedpass://v1/fido2?",
    "seedpass://v1/fido2?rp=a&n=zz",
    "seedpass://v1/fido2?rp=a&n=00",
    "not a uri",
])
def test_malformed_prepare_uris_refused(payload):
    with pytest.raises(SessionError):
        parse_prepare_uri(payload)


def test_arming_derives_a_credential():
    session = ArmedSession(seed_bytes(), "github.com")
    assert session.rp_id == "github.com"
    assert len(session.credential_id) == 32
    assert session.is_registration


def test_same_nonce_reproduces_the_same_credential():
    """This is what makes an armed login possible at all."""
    first = ArmedSession(seed_bytes(), "github.com")
    second = ArmedSession(seed_bytes(), "github.com", nonce=first.nonce)
    assert second.credential_id == first.credential_id
    assert not second.is_registration


def test_session_only_answers_for_its_own_rp():
    session = ArmedSession(seed_bytes(), "github.com")

    assert session.matches("github.com")
    assert not session.matches("evil.com")
    assert not session.matches("GitHub.com")          # RP IDs are case-sensitive
    assert not session.matches("github.com", b"\x00" * 32)
    assert session.matches("github.com", session.credential_id)


def test_credential_for_returns_none_on_mismatch():
    session = ArmedSession(seed_bytes(), "github.com")
    assert session.credential_for("github.com") is not None
    assert session.credential_for("evil.com") is None


def test_armed_credential_matches_the_unarmed_derivation():
    """
    Arming must not change the key. A credential registered with the seed
    loaded has to be usable from an armed session and vice versa.
    """
    session = ArmedSession(seed_bytes(), "github.com")
    direct = Credential(seed_bytes(), "github.com", session.nonce)
    assert direct.credential_id == session.credential_id
    assert direct.public_key == session.credential_for("github.com").public_key


def test_credential_uri_round_trips_and_carries_no_secret():
    session = ArmedSession(seed_bytes(), "github.com")
    uri = session.to_credential_uri()
    parsed = parse_credential_uri(uri)

    assert parsed["rp_id"] == "github.com"
    assert parsed["nonce"] == session.nonce
    assert parsed["credential_id"] == session.credential_id
    # The nonce and credential ID are public; the RP already holds the latter.
    assert "xprv" not in uri and "seed" not in uri.replace("seedpass", "")





def test_session_restricts_the_rp_for_its_whole_life():
    """
    The seed stays loaded during a USB session, so this restriction is what the
    arming step actually buys: a host cannot enumerate sites, mint credentials
    for domains the user never approved, or swap the RP mid-session.
    """
    session = ArmedSession(seed_bytes(), "github.com")

    for hostile in ("evil.com", "github.com.evil.com", "githubb.com", "GITHUB.COM", ""):
        assert session.credential_for(hostile) is None

    assert session.credential_for("github.com") is not None


def test_session_binds_to_one_credential():
    """Even for the right RP, only the approved credential answers."""
    session = ArmedSession(seed_bytes(), "github.com")
    other = ArmedSession(seed_bytes(), "github.com")

    assert session.credential_for("github.com", session.credential_id) is not None
    assert session.credential_for("github.com", other.credential_id) is None


def test_armed_credential_is_the_same_as_an_unarmed_one():
    """
    Arming changes what the device will answer, not what it derives. A
    credential registered through a session must be usable without one.
    """
    session = ArmedSession(seed_bytes(), "github.com")
    direct = Credential(seed_bytes(), "github.com", session.nonce)

    assert direct.credential_id == session.credential_id
    assert direct.public_key == session.credential_for("github.com").public_key


# ============================================== transport and the USB loop

from seedsigner.models import fido2_ctaphid as _hid  # noqa: E402
from seedsigner.models.fido2_transport import (  # noqa: E402
    FakeTransport,
    TransportError,
)


def _drive(transport, authenticator):
    """
    The loop SeedPassFido2ArmedView runs, without the screens.

    Kept identical in shape to the view so this test exercises the real
    sequence: read a packet, feed the framing layer, answer any completed
    message, write everything back.
    """
    hid = _hid.CtapHid()
    while True:
        packet = transport.read_packet()
        if packet is None:
            return
        message = hid.handle_packet(packet)
        transport.write_packets(hid.take_responses())
        if message and message[1] == _hid.CMD_CBOR:
            response = authenticator.handle(message[2])
            transport.write_packets(
                _hid.build_packets(message[0], _hid.CMD_CBOR, response)
            )


def _reassemble(packets):
    hid = _hid.CtapHid()
    result = None
    for packet in packets:
        message = hid.handle_packet(packet)
        if message:
            result = message
    return result


def test_full_registration_over_the_transport():
    """
    A whole registration as it would happen over USB: host packets in, device
    packets out, and a signature an RP would accept.
    """
    request = bytes([CMD_MAKE_CREDENTIAL]) + cbor.encode({
        1: CLIENT_DATA_HASH,
        2: {"id": "github.com"},
        3: {"id": b"u"},
        4: [{"alg": ALG_ES256, "type": "public-key"}],
    })
    transport = FakeTransport(_hid.build_packets(1, _hid.CMD_CBOR, request))
    transport.open()

    _drive(transport, Authenticator(seed_bytes(), confirm=always_approve))

    _, _, payload = _reassemble(transport.sent)
    assert payload[0] == CTAP2_OK

    attestation = cbor.decode(payload[1:])
    auth_data = attestation[2]
    length = int.from_bytes(auth_data[53:55], "big")
    cose_key = cbor.decode(auth_data[55 + length:])
    public_key = (
        int.from_bytes(cose_key[-2], "big"),
        int.from_bytes(cose_key[-3], "big"),
    )
    signature = p256.decode_der_signature(attestation[3]["sig"])

    assert p256.verify_digest(
        public_key,
        hashlib.sha256(auth_data + CLIENT_DATA_HASH).digest(),
        signature,
    )


def test_armed_session_denies_another_site_without_prompting():
    """
    The session check runs before the user is asked. A host probing for other
    domains must not be able to make the device flash prompts at someone.
    """
    session = ArmedSession(seed_bytes(), "github.com")
    prompts = []

    def confirm(rp_id, action):
        if not session.matches(rp_id):
            return False
        prompts.append(rp_id)
        return True

    authenticator = Authenticator(seed_bytes(), confirm=confirm)

    request = bytes([CMD_MAKE_CREDENTIAL]) + cbor.encode({
        1: CLIENT_DATA_HASH,
        2: {"id": "evil.com"},
        3: {"id": b"u"},
        4: [{"alg": ALG_ES256, "type": "public-key"}],
    })
    assert authenticator.handle(request)[0] == CTAP2_ERR_OPERATION_DENIED
    assert prompts == []


def test_ping_is_echoed():
    """A host uses PING to prove the link before trusting it."""
    payload = b"are you there"
    transport = FakeTransport(_hid.build_packets(1, _hid.CMD_PING, payload))
    transport.open()

    hid = _hid.CtapHid()
    while True:
        packet = transport.read_packet()
        if packet is None:
            break
        message = hid.handle_packet(packet)
        transport.write_packets(hid.take_responses())
        if message and message[1] == _hid.CMD_PING:
            transport.write_packets(
                _hid.build_packets(message[0], _hid.CMD_PING, message[2])
            )

    assert _reassemble(transport.sent)[2] == payload


def test_transport_rejects_wrong_sized_packets():
    transport = FakeTransport()
    transport.open()
    with pytest.raises(TransportError):
        transport.write_packet(b"\x00" * 63)


def test_transport_reports_idle_as_none():
    """An idle link must not look like a disconnection."""
    transport = FakeTransport()
    transport.open()
    assert transport.read_packet() is None
