"""
Tests for seedsigner.models.seedpass_identity.

Run from the SeedSigner repo root:
    python -m pytest tests/test_seedpass_identity.py -v
"""
import hashlib
import struct

import pytest

from embit import bip39

from seedsigner.models.seedpass import PasswordFormat, derive_password
from seedsigner.models.seedpass_identity import (
    IdentityError,
    LABEL_URI_SCHEME,
    MAX_HIDDEN_CHALLENGE_BYTES,
    MAX_VISUAL_CHALLENGE_CHARS,
    challenge_digest,
    derive_identity,
    label_for_uri,
    parse_auth_request,
    path_to_string,
    sign_challenge,
    slip13_path,
    uri_for_label,
    validate_uri,
)


TEST_MNEMONIC_24 = " ".join(["abandon"] * 23 + ["art"])


def seed_bytes_for(mnemonic: str = TEST_MNEMONIC_24, passphrase: str = "") -> bytes:
    return bip39.mnemonic_to_seed(mnemonic, password=passphrase)


# ------------------------------------------------------------- the SLIP-13 vector

def test_matches_the_slip13_worked_example():
    """
    The worked example from SLIP-0013 itself. If this fails, identities derived
    here would not match any other implementation of the standard.
    """
    path = slip13_path("https://satoshi@bitcoin.org/login", 0)

    assert path == [
        2147483661,   # 13'
        2637750992,   # A'
        2845082444,   # B'
        3761103859,   # C'
        4005495825,   # D'
    ]


def test_intermediate_values_of_the_worked_example():
    """Each step of the spec, so a failure says which step broke."""
    uri = "https://satoshi@bitcoin.org/login"
    digest = hashlib.sha256(struct.pack("<I", 0) + uri.encode()).digest()

    assert digest.hex() == (
        "d0e2389d4c8394a9f3e32de01104bf6e8db2d9e2bb0905d60fffa5a18fd696db"
    )
    assert digest[:16].hex() == "d0e2389d4c8394a9f3e32de01104bf6e"
    assert struct.unpack("<4I", digest[:16]) == (
        2637750992, 2845082444, 3761103859, 1858012177,
    )


def test_every_path_component_is_hardened():
    for uri in ("https://example.com", "ssh://root@example.com:2222", "seedpass://gmail"):
        for child in slip13_path(uri, 0):
            assert child & 0x80000000, f"{uri} produced an unhardened component"


def test_path_renders_readably():
    assert path_to_string(slip13_path("https://satoshi@bitcoin.org/login", 0)).startswith("m/13'/")


def test_index_changes_the_path():
    assert slip13_path("https://example.com", 0) != slip13_path("https://example.com", 1)


def test_different_uris_give_different_paths():
    uris = ["https://example.com", "https://example.org", "https://example.com/login"]
    paths = {tuple(slip13_path(u, 0)) for u in uris}
    assert len(paths) == len(uris)


@pytest.mark.parametrize("bad_index", [-1, 2**32])
def test_out_of_range_index_rejected(bad_index):
    with pytest.raises(IdentityError):
        slip13_path("https://example.com", bad_index)


# ------------------------------------------------------------- labels as URIs

def test_label_becomes_a_uri():
    assert uri_for_label("gmail") == f"{LABEL_URI_SCHEME}://gmail"
    assert uri_for_label("  GMAIL ") == f"{LABEL_URI_SCHEME}://gmail"


def test_label_uri_round_trips():
    assert label_for_uri(uri_for_label("my bank")) == "my bank"


def test_real_uris_are_not_mistaken_for_labels():
    assert label_for_uri("https://example.com") is None


def test_label_normalisation_matches_the_password_rules():
    """
    A user who types "Gmail" for a password and "gmail" for an identity should
    not end up with two different identities.
    """
    seed_bytes = seed_bytes_for()
    assert (
        derive_identity(seed_bytes, label="Gmail").public_key
        == derive_identity(seed_bytes, label="  gmail  ").public_key
    )


@pytest.mark.parametrize("bad", ["", "   ", "caf\u00e9!", "a" * 65])
def test_invalid_labels_rejected(bad):
    with pytest.raises(IdentityError):
        derive_identity(seed_bytes_for(), label=bad)


# ------------------------------------------------------------- URI validation

@pytest.mark.parametrize("uri", [
    "https://example.com",
    "ftp://public@example.com/pub",
    "ssh://root@example.com:2222",
    "seedpass://gmail",
])
def test_valid_uris_accepted(uri):
    assert validate_uri(uri) == uri


@pytest.mark.parametrize("bad", ["", "example.com", "/just/a/path", "https://", "x" * 300])
def test_invalid_uris_rejected(bad):
    with pytest.raises(IdentityError):
        validate_uri(bad)


# ------------------------------------------------------------- derivation

def test_identity_is_deterministic():
    a = derive_identity(seed_bytes_for(), uri="https://example.com")
    b = derive_identity(seed_bytes_for(), uri="https://example.com")
    assert a.public_key == b.public_key
    assert a.address == b.address


def test_public_key_is_a_compressed_secp256k1_point():
    identity = derive_identity(seed_bytes_for(), label="gmail")
    assert len(identity.public_key) == 66              # 33 bytes hex
    assert identity.public_key[:2] in ("02", "03")


def test_address_is_bech32():
    assert derive_identity(seed_bytes_for(), label="gmail").address.startswith("bc1")


def test_rotation_changes_the_identity():
    seed_bytes = seed_bytes_for()
    a = derive_identity(seed_bytes, label="gmail", index=0)
    b = derive_identity(seed_bytes, label="gmail", index=1)
    assert a.public_key != b.public_key


def test_different_seed_gives_a_different_identity():
    a = derive_identity(seed_bytes_for(), label="gmail")
    b = derive_identity(seed_bytes_for(passphrase="extra"), label="gmail")
    assert a.public_key != b.public_key
    assert a.fingerprint != b.fingerprint


def test_requires_exactly_one_of_uri_or_label():
    with pytest.raises(IdentityError):
        derive_identity(seed_bytes_for())
    with pytest.raises(IdentityError):
        derive_identity(seed_bytes_for(), uri="https://example.com", label="gmail")


def test_export_uri_carries_the_public_key_and_no_secret():
    identity = derive_identity(seed_bytes_for(), label="my bank")
    exported = identity.to_uri()

    assert exported.startswith("seedpass://v1/pubkey?")
    assert identity.public_key in exported
    assert "my%20bank" in exported
    # Nothing private should ever appear in an export.
    assert "xprv" not in exported


# ------------------------------------------------------------- challenges

def test_challenge_digest_is_two_concatenated_hashes():
    hidden = bytes.fromhex("deadbeef")
    visual = "2026-08-15 21:00:00"

    assert challenge_digest(hidden, visual) == (
        hashlib.sha256(hidden).digest() + hashlib.sha256(visual.encode()).digest()
    )
    assert len(challenge_digest(hidden, visual)) == 64


def test_oversized_challenges_rejected():
    with pytest.raises(IdentityError):
        challenge_digest(b"x" * (MAX_HIDDEN_CHALLENGE_BYTES + 1), "ok")
    with pytest.raises(IdentityError):
        challenge_digest(b"", "x" * (MAX_VISUAL_CHALLENGE_CHARS + 1))


def test_signature_is_deterministic_and_base64():
    import base64

    seed_bytes = seed_bytes_for()
    args = dict(uri="seedpass://gmail", hidden=bytes.fromhex("deadbeef"), visual="hello")

    first = sign_challenge(seed_bytes, **args)
    assert first == sign_challenge(seed_bytes, **args)
    assert len(base64.b64decode(first)) == 65        # recoverable Bitcoin signature


def test_signature_changes_with_the_challenge():
    seed_bytes = seed_bytes_for()
    a = sign_challenge(seed_bytes, "seedpass://gmail", b"\x01", "hello")
    b = sign_challenge(seed_bytes, "seedpass://gmail", b"\x02", "hello")
    c = sign_challenge(seed_bytes, "seedpass://gmail", b"\x01", "goodbye")
    assert len({a, b, c}) == 3


def test_signature_changes_with_the_identity():
    seed_bytes = seed_bytes_for()
    a = sign_challenge(seed_bytes, "https://example.com", b"\x01", "hello")
    b = sign_challenge(seed_bytes, "https://example.org", b"\x01", "hello")
    assert a != b


# ------------------------------------------------------------- auth requests

def test_auth_request_round_trips():
    parsed = parse_auth_request(
        "seedpass://v1/auth?id=https%3A%2F%2Fexample.com&idx=2"
        "&h=deadbeef&v=2026-08-15%2021%3A00%3A00"
    )
    assert parsed["uri"] == "https://example.com"
    assert parsed["index"] == 2
    assert parsed["hidden"] == bytes.fromhex("deadbeef")
    assert parsed["visual"] == "2026-08-15 21:00:00"


def test_auth_request_defaults():
    parsed = parse_auth_request("seedpass://v1/auth?id=https%3A%2F%2Fexample.com")
    assert parsed["index"] == 0
    assert parsed["hidden"] == b""
    assert parsed["visual"] == ""


@pytest.mark.parametrize("bad", [
    "not a seedpass uri",
    "seedpass://v1/secret?fp=5436d724",                      # a password payload
    "seedpass://v1/auth?idx=0",                              # no identity
    "seedpass://v1/auth?id=example.com",                     # unusable URI
    "seedpass://v1/auth?id=https%3A%2F%2Fa.com&h=nothex",
    "seedpass://v1/auth?id=https%3A%2F%2Fa.com&idx=abc",
])
def test_malformed_auth_requests_rejected(bad):
    with pytest.raises(IdentityError):
        parse_auth_request(bad)


def test_oversized_challenge_rejected_at_parse_time():
    """Rejected before the user is ever shown something to approve."""
    with pytest.raises(IdentityError):
        parse_auth_request(
            "seedpass://v1/auth?id=https%3A%2F%2Fa.com&h=" + "ab" * 65
        )


# ------------------------------------------------- passwords must be untouched

def test_identities_do_not_disturb_passwords():
    """
    Identities live at m/13' and passwords at m/83696968'. Different purpose
    branches of the same seed, so adding identities must not move a single
    password. These are the values the device produced before identities existed.
    """
    seed_bytes = seed_bytes_for()

    assert derive_password(seed_bytes, label="gmail", fmt=PasswordFormat.FULL).password == (
        "6w8BYxxBW7nx2s9qJkFxn6jGh69GYJYhoJm5W2tfGa1v!2"
    )
    assert derive_password(seed_bytes, label="gmail", fmt=PasswordFormat.SHORT).password == (
        "vugQwXTAY2wMna!2"
    )
    assert derive_password(seed_bytes, label="my bank", fmt=PasswordFormat.FULL).password == (
        "B5ghY5H9BRMMbjQQgyU6GxABW83aScvZUyCLBKpfYqNG!2"
    )
    assert derive_password(seed_bytes, label="my bank", fmt=PasswordFormat.SHORT).password == (
        "9oU3Ae3XW4Aebi!2"
    )


def test_password_and_identity_paths_cannot_collide():
    from seedsigner.models.seedpass import BIP85_APP_HEX

    # Passwords: m/83696968'/128169'/...  Identities: m/13'/...
    assert slip13_path("seedpass://gmail", 0)[0] == (13 | 0x80000000)
    assert BIP85_APP_HEX == 128169
    assert (13 | 0x80000000) != (83696968 | 0x80000000)
