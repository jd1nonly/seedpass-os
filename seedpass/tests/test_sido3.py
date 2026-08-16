"""
Tests for SIDO3: WebAuthn signing relayed to an air-gapped device over QR.

The weight is on `validate_rp_id_for_origin`. Everything else here is
encoding; that function is the entire phishing-resistance story, and it is the
one place where a bug turns a login into a giveaway.

Run from the SeedSigner repo root:
    python -m pytest tests/test_sido3.py -v
"""
import base64
import hashlib

import pytest

from embit import bip39

from seedsigner.models import fido2_cbor as cbor
from seedsigner.models import p256
from seedsigner.models.fido2_credential import Credential
from seedsigner.models.sido3 import (
    CREATE_REQUEST_PREFIX,
    GET_REQUEST_PREFIX,
    Sido3Error,
    build_create_request,
    build_get_request,
    client_data_hash_for,
    origin_effective_domain,
    parse_create_request,
    parse_create_response,
    parse_get_request,
    parse_get_response,
    parse_request,
    sign_request,
    validate_rp_id_for_origin,
)

TEST_MNEMONIC = " ".join(["abandon"] * 23 + ["art"])
CHALLENGE = base64.urlsafe_b64encode(b"\x01" * 32).decode().rstrip("=")


def seed_bytes(passphrase: str = "") -> bytes:
    return bip39.mnemonic_to_seed(TEST_MNEMONIC, password=passphrase)


# ================================================== the origin check

@pytest.mark.parametrize("rp_id,origin,reason", [
    ("example.com", "https://example.com", "exact match"),
    ("example.com", "https://login.example.com", "registrable suffix"),
    ("example.com", "https://a.b.c.example.com", "deep subdomain"),
    ("example.com", "https://example.com:8443", "explicit port"),
    ("localhost", "http://localhost", "localhost development exception"),
    ("EXAMPLE.com", "https://example.com", "case insensitive"),
])
def test_legitimate_rp_ids_accepted(rp_id, origin, reason):
    assert validate_rp_id_for_origin(rp_id, origin) == rp_id.lower()


@pytest.mark.parametrize("rp_id,origin,attack", [
    ("example.com", "https://evil-example.com",
     "label boundary -- the classic near-miss domain"),
    ("example.com", "https://example.com.evil.net",
     "suffix confusion -- victim domain as a prefix"),
    ("evil.com", "https://example.com",
     "wholly unrelated domain"),
    ("com", "https://example.com",
     "bare TLD, which would match every site under it"),
    ("co.uk", "https://example.co.uk",
     "public suffix"),
    ("login.example.com", "https://example.com",
     "RP ID more specific than the origin"),
    ("example.com", "http://example.com",
     "plain http, so a network attacker could rewrite the page"),
    ("example.com", "ftp://example.com",
     "non-web scheme"),
    ("example.com", "not a url",
     "unparseable origin"),
    ("example.com", "",
     "empty origin"),
])
def test_phishing_shaped_rp_ids_refused(rp_id, origin, attack):
    with pytest.raises(Sido3Error):
        validate_rp_id_for_origin(rp_id, origin)


@pytest.mark.parametrize("rp_id", [
    "", "   ", "a" * 300,
    "example.com\nevil.com",
    "example.com\x00evil",
    " example.com",
    "exam ple.com",
])
def test_malformed_rp_ids_refused(rp_id):
    """
    The user reads this on a 240px screen. A newline or a padded string could
    push the real domain out of view, so these are refused before display.
    """
    with pytest.raises(Sido3Error):
        validate_rp_id_for_origin(rp_id, "https://example.com")


def test_origin_effective_domain_lowercases():
    assert origin_effective_domain("https://EXAMPLE.com/path") == "example.com"


# ================================================== requests

def test_create_request_round_trips():
    digest = client_data_hash_for(CHALLENGE, "https://login.example.com", "create")
    payload = build_create_request(
        "example.com", "https://login.example.com", digest, user_name="joao",
    )
    parsed = parse_create_request(payload)

    assert parsed["operation"] == "create"
    assert parsed["rp_id"] == "example.com"
    assert parsed["origin"] == "https://login.example.com"
    assert parsed["client_data_hash"] == digest
    assert parsed["user_name"] == "joao"


def test_get_request_round_trips():
    credential = Credential(seed_bytes(), "example.com", b"\x01" * 16)
    digest = client_data_hash_for(CHALLENGE, "https://example.com", "get")
    payload = build_get_request(
        "example.com", "https://example.com", digest, credential.credential_id,
    )
    parsed = parse_get_request(payload)

    assert parsed["operation"] == "get"
    assert parsed["credential_id"] == credential.credential_id


def test_parse_request_dispatches_on_type():
    digest = client_data_hash_for(CHALLENGE, "https://example.com", "create")
    create = build_create_request("example.com", "https://example.com", digest)
    assert parse_request(create)["operation"] == "create"


def test_building_a_request_for_a_mismatched_origin_is_refused():
    """
    Caught when the request is built, not only when it is parsed. The companion
    app should not be able to produce a QR the device will refuse.
    """
    digest = client_data_hash_for(CHALLENGE, "https://evil.com", "create")
    with pytest.raises(Sido3Error):
        build_create_request("example.com", "https://evil.com", digest)


@pytest.mark.parametrize("payload", [
    "not a sido3 uri",
    "seedpass://v1/secret?fp=x",
    CREATE_REQUEST_PREFIX + "rp=example.com",                      # no origin
    CREATE_REQUEST_PREFIX + "or=https://example.com",              # no rp
    CREATE_REQUEST_PREFIX + "rp=example.com&or=https://example.com&cdh=zz",
    CREATE_REQUEST_PREFIX + "rp=example.com&or=https://example.com&cdh=00",
    GET_REQUEST_PREFIX + "rp=example.com&or=https://example.com&cdh=" + "00" * 32,
])
def test_malformed_requests_refused(payload):
    with pytest.raises(Sido3Error):
        parse_request(payload)


def test_duplicate_fields_refused():
    """
    Two values for one field is how a relay bug or an attacker gets a parser to
    disagree with whatever produced the payload.
    """
    digest = client_data_hash_for(CHALLENGE, "https://example.com", "create")
    payload = build_create_request("example.com", "https://example.com", digest)
    with pytest.raises(Sido3Error):
        parse_request(payload + "&rp=evil.com")


def test_wrong_length_credential_id_refused():
    digest = client_data_hash_for(CHALLENGE, "https://example.com", "get")
    payload = (
        GET_REQUEST_PREFIX + "rp=example.com&or=https://example.com"
        + "&cdh=" + digest.hex() + "&cid=" + "00" * 16
    )
    with pytest.raises(Sido3Error):
        parse_request(payload)


# ================================================== signing, end to end

def _register(origin="https://login.example.com", rp_id="example.com"):
    digest = client_data_hash_for(CHALLENGE, origin, "create")
    request = parse_request(build_create_request(rp_id, origin, digest, user_name="joao"))
    response = parse_create_response(sign_request(seed_bytes(), request))

    auth_data = response["authenticator_data"]
    length = int.from_bytes(auth_data[53:55], "big")
    credential_id = auth_data[55:55 + length]
    cose_key = cbor.decode(auth_data[55 + length:])
    public_key = (
        int.from_bytes(cose_key[-2], "big"),
        int.from_bytes(cose_key[-3], "big"),
    )
    return credential_id, public_key, auth_data, response["signature"], digest


def test_registration_signature_verifies_as_a_relying_party_would():
    _, public_key, auth_data, signature, digest = _register()

    assert p256.verify_digest(
        public_key,
        hashlib.sha256(auth_data + digest).digest(),
        p256.decode_der_signature(signature),
    )


def test_assertion_signature_verifies():
    credential_id, public_key, _, _, _ = _register()

    origin = "https://login.example.com"
    digest = client_data_hash_for(CHALLENGE, origin, "get")
    request = parse_request(build_get_request("example.com", origin, digest, credential_id))
    response = parse_get_response(sign_request(seed_bytes(), request))

    assert response["credential_id"] == credential_id
    assert p256.verify_digest(
        public_key,
        hashlib.sha256(response["authenticator_data"] + digest).digest(),
        p256.decode_der_signature(response["signature"]),
    )


def test_client_data_hash_differs_between_create_and_get():
    """
    The type field is part of clientDataJSON, so a registration signature cannot
    be replayed as an assertion.
    """
    origin = "https://example.com"
    assert (
        client_data_hash_for(CHALLENGE, origin, "create")
        != client_data_hash_for(CHALLENGE, origin, "get")
    )


def test_client_data_hash_binds_the_origin():
    """A signature for one origin must not verify for another."""
    assert (
        client_data_hash_for(CHALLENGE, "https://example.com", "get")
        != client_data_hash_for(CHALLENGE, "https://evil.com", "get")
    )


def test_credential_from_another_seed_is_refused():
    credential_id, _, _, _, _ = _register()

    origin = "https://login.example.com"
    digest = client_data_hash_for(CHALLENGE, origin, "get")
    request = parse_request(build_get_request("example.com", origin, digest, credential_id))

    with pytest.raises(Sido3Error):
        sign_request(seed_bytes("different"), request)


def test_forged_credential_id_is_refused():
    import os

    origin = "https://example.com"
    digest = client_data_hash_for(CHALLENGE, origin, "get")
    request = parse_request(
        build_get_request("example.com", origin, digest, os.urandom(32))
    )
    with pytest.raises(Sido3Error):
        sign_request(seed_bytes(), request)


# ================================================== QR sizing

def test_every_payload_fits_a_single_qr_frame():
    """
    Animated QR would double the human effort at both ends. These stay well
    inside what one frame holds at a legible module size on a 240x240 screen.
    """
    credential_id, _, auth_data, signature, digest = _register()
    origin = "https://login.example.com"

    create_request = build_create_request("example.com", origin, digest, user_name="joao")
    get_request = build_get_request("example.com", origin, digest, credential_id)

    request = parse_request(create_request)
    create_response = sign_request(seed_bytes(), request)
    get_response = sign_request(
        seed_bytes(), parse_request(get_request),
    )

    for name, payload in [
        ("create request", create_request),
        ("get request", get_request),
        ("create response", create_response),
        ("get response", get_response),
    ]:
        assert len(payload) < 800, f"{name} is {len(payload)} chars"
