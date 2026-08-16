"""
Tests for seedsigner.models.seedpass.

Run from the SeedSigner repo root:
    python -m pytest tests/test_seedpass.py -v
"""
import re

import pytest

from embit import bip39

from seedsigner.models import seedpass
from seedsigner.models.seedpass import (
    B58_ALPHABET,
    BIP85_APP_HEX,
    BIP85_MAX_INDEX,
    DEFAULT_FORMAT,
    PASSWORD_SUFFIX,
    PasswordFormat,
    SeedPassError,
    b58_decode,
    b58_encode_fixed,
    decode_password,
    derive_password,
    encode_password,
    index_from_label,
    normalize_label,
    parse_uri,
    satisfies_charset_policy,
)


# BIP-85 reference master key from the BIP text
BIP85_TEST_XPRV = (
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
)

# A stable 24-word mnemonic used for the rest of the tests
TEST_MNEMONIC_24 = " ".join(["abandon"] * 23 + ["art"])

# Glyph pairs base58 exists to avoid
AMBIGUOUS_GLYPHS = set("0OIl")

BASE58_ONLY = re.compile(r"^[" + B58_ALPHABET + r"]+$")


def seed_bytes_for(mnemonic: str, passphrase: str = "") -> bytes:
    return bip39.mnemonic_to_seed(mnemonic, password=passphrase)


def base58_part(password: str) -> str:
    return password[: -len(PASSWORD_SUFFIX)]


# ---------------------------------------------------------------- the alphabet

def test_alphabet_is_bitcoin_base58():
    assert len(B58_ALPHABET) == 58
    assert len(set(B58_ALPHABET)) == 58
    assert not (AMBIGUOUS_GLYPHS & set(B58_ALPHABET))


def test_no_ambiguous_glyphs_in_any_password():
    """The whole reason for base58 over base64url."""
    seed_bytes = seed_bytes_for(TEST_MNEMONIC_24)
    for fmt in PasswordFormat.ALL:
        for n in range(50):
            pw = derive_password(seed_bytes, label=f"site-{n}", fmt=fmt).password
            assert not (AMBIGUOUS_GLYPHS & set(pw)), pw


# ---------------------------------------------------------------- base58 codec

def test_encode_is_fixed_width_and_zero_padded():
    assert b58_encode_fixed(0, 5) == "11111"          # '1' is base58's zero
    assert len(b58_encode_fixed(57, 5)) == 5
    assert b58_encode_fixed(57, 1) == B58_ALPHABET[57]


def test_encode_decode_round_trip():
    for value in (0, 1, 57, 58, 12345, 2**200):
        assert b58_decode(b58_encode_fixed(value, 44)) == value


def test_encode_truncates_high_digits_when_too_narrow():
    """Documented behaviour: the result is `value mod 58**num_chars`."""
    assert b58_decode(b58_encode_fixed(58 * 3 + 7, 1)) == 7


def test_decode_rejects_a_non_base58_char():
    with pytest.raises(SeedPassError):
        b58_decode("abc0def")     # '0' is not in the alphabet


def test_encode_rejects_negative():
    with pytest.raises(SeedPassError):
        b58_encode_fixed(-1, 4)


# ---------------------------------------------------------------- BIP-85

def test_matches_official_bip85_hex_vector():
    """
    The BIP-85 text publishes the 64-byte HEX result for
    m/83696968'/128169'/64'/0'. Our entropy source must reproduce it.
    """
    from embit import bip32, bip85

    root = bip32.HDKey.from_base58(BIP85_TEST_XPRV)
    entropy = bip85.derive_entropy(root, BIP85_APP_HEX, [64, 0])[:64]

    assert entropy.hex() == (
        "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f8785"
        "55d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c"
    )


def test_password_is_base58_of_the_bip85_entropy(monkeypatch):
    from embit import bip32, bip85

    root = bip32.HDKey.from_base58(BIP85_TEST_XPRV)

    def fake_entropy(seed_bytes, num_bytes, index):
        return bip85.derive_entropy(root, BIP85_APP_HEX, [num_bytes, index])[:num_bytes]

    monkeypatch.setattr(seedpass, "_bip85_entropy", fake_entropy)

    result = seedpass.derive_password(b"ignored", index=0)
    expected = b58_encode_fixed(int.from_bytes(fake_entropy(None, 32, 0), "big"), 44)
    assert result.password == expected + PASSWORD_SUFFIX


def test_the_two_formats_use_different_path_levels():
    """
    num_bytes is a BIP-85 path level, so short and full are independent
    derivations -- knowing one leaks nothing about the other.
    """
    seed_bytes = seed_bytes_for(TEST_MNEMONIC_24)
    full = derive_password(seed_bytes, index=7, fmt=PasswordFormat.FULL)
    short = derive_password(seed_bytes, index=7, fmt=PasswordFormat.SHORT)

    assert full.derivation_path == "m/83696968'/128169'/32'/7'"
    assert short.derivation_path == "m/83696968'/128169'/16'/7'"
    assert base58_part(short.password) not in base58_part(full.password)


# ---------------------------------------------------------------- formats

def test_only_two_formats_and_no_128_bit_option():
    assert PasswordFormat.ALL == [PasswordFormat.FULL, PasswordFormat.SHORT]
    assert DEFAULT_FORMAT == PasswordFormat.FULL
    assert PasswordFormat.num_bits(PasswordFormat.FULL) == 256


@pytest.mark.parametrize("fmt,length,bits", [
    (PasswordFormat.FULL, 46, 256),
    (PasswordFormat.SHORT, 16, 82),
])
def test_lengths_and_bits_are_fixed_per_format(fmt, length, bits):
    assert PasswordFormat.char_length(fmt) == length
    result = derive_password(seed_bytes_for(TEST_MNEMONIC_24), label="gmail", fmt=fmt)
    assert result.char_length == length
    assert result.num_bits == bits
    assert BASE58_ONLY.match(base58_part(result.password))


def test_short_format_fits_a_16_char_limit():
    seed_bytes = seed_bytes_for(TEST_MNEMONIC_24)
    for n in range(100):
        pw = derive_password(seed_bytes, label=f"site-{n}", fmt=PasswordFormat.SHORT).password
        assert len(pw) == 16


def test_full_format_preserves_all_256_bits():
    """44 base58 digits hold 2**257.8, so nothing is discarded."""
    assert 58**44 > 2**256

    result = derive_password(seed_bytes_for(TEST_MNEMONIC_24), label="gmail")
    value = decode_password(result.password, PasswordFormat.FULL)
    assert 0 <= value < 2**256
    assert encode_password(value.to_bytes(32, "big"), PasswordFormat.FULL) == result.password


def test_short_format_is_deliberately_lossy():
    """14 digits hold 2**82; the 128-bit source is not recoverable."""
    assert 58**14 < 2**128

    result = derive_password(seed_bytes_for(TEST_MNEMONIC_24), label="gmail",
                             fmt=PasswordFormat.SHORT)
    assert decode_password(result.password, PasswordFormat.SHORT) < 58**14


def test_decode_rejects_the_wrong_format():
    result = derive_password(seed_bytes_for(TEST_MNEMONIC_24), label="gmail")
    with pytest.raises(SeedPassError):
        decode_password(result.password, PasswordFormat.SHORT)


def test_decode_rejects_a_missing_suffix():
    with pytest.raises(SeedPassError):
        decode_password("9oU3Ae3XW4Aebi")


def test_unknown_format_rejected():
    with pytest.raises(SeedPassError):
        derive_password(seed_bytes_for(TEST_MNEMONIC_24), label="gmail", fmt="b58-128")


# ------------------------------------------------- site-requirement formatting

def test_password_ends_with_the_suffix():
    for fmt in PasswordFormat.ALL:
        result = derive_password(seed_bytes_for(TEST_MNEMONIC_24), label="gmail", fmt=fmt)
        assert result.password.endswith(PASSWORD_SUFFIX)


def test_password_satisfies_the_usual_site_rules():
    """Upper, lower, digit and symbol -- the common four."""
    seed_bytes = seed_bytes_for(TEST_MNEMONIC_24)
    for fmt in PasswordFormat.ALL:
        for n in range(50):
            pw = derive_password(seed_bytes, label=f"site-{n}", fmt=fmt).password
            assert any(c.isupper() for c in pw), pw
            assert any(c.islower() for c in pw), pw
            assert any(c.isdigit() for c in pw), pw
            assert any(not c.isalnum() for c in pw), pw


def test_charset_policy_helper():
    assert satisfies_charset_policy("aB!2")
    assert not satisfies_charset_policy("ABCD!2")
    assert not satisfies_charset_policy("abcd!2")


# ---------------------------------------------------------------- display chunks

def test_chunks_rejoin_into_the_password():
    """
    The device shows groups; a user types them with nothing in between. That
    round-trip has to be exact.
    """
    seed_bytes = seed_bytes_for(TEST_MNEMONIC_24)
    for fmt, size in ((PasswordFormat.FULL, 10), (PasswordFormat.SHORT, 8)):
        result = derive_password(seed_bytes, label="gmail", fmt=fmt)
        chunks = result.chunks(size)
        assert "".join(chunks) == result.password
        assert all(len(chunk) <= size for chunk in chunks)


def test_chunk_counts_stay_screen_sized():
    seed_bytes = seed_bytes_for(TEST_MNEMONIC_24)
    assert len(derive_password(seed_bytes, label="gmail").chunks(10)) == 5
    assert len(derive_password(seed_bytes, label="gmail",
                               fmt=PasswordFormat.SHORT).chunks(8)) == 2


# ---------------------------------------------------------------- label handling

@pytest.mark.parametrize("raw", ["Gmail", "  gmail ", "GMAIL", "gmail"])
def test_label_normalization_is_case_and_space_insensitive(raw):
    assert normalize_label(raw) == "gmail"


def test_label_with_spaces_is_collapsed():
    assert normalize_label("  My   Bank  Login ") == "my bank login"


def test_tabs_and_newlines_normalize_to_single_spaces():
    assert normalize_label("my\tbank\nlogin") == "my bank login"


@pytest.mark.parametrize("raw", ["Gmail", " My  Bank ", "a\u00dfb", "PROTON.ME"])
def test_normalization_is_idempotent(raw):
    once = normalize_label(raw)
    assert normalize_label(once) == once


@pytest.mark.parametrize("bad", ["", "   ", "caf\u00e9!", "a" * 65, "pass=word", "50%"])
def test_invalid_labels_rejected(bad):
    with pytest.raises(SeedPassError):
        normalize_label(bad)


def test_index_from_label_is_deterministic_and_in_range():
    first = index_from_label("gmail")
    assert first == index_from_label("  GMAIL  ")
    assert 0 <= first <= BIP85_MAX_INDEX


def test_counter_rotates_the_index():
    assert index_from_label("gmail", 0) != index_from_label("gmail", 1)


def test_different_labels_give_different_indices():
    labels = ["gmail", "github", "my bank", "proton.me", "aws-prod"]
    indices = {index_from_label(label) for label in labels}
    assert len(indices) == len(labels)


# ---------------------------------------------------------------- derivation

def test_same_inputs_give_same_password():
    seed_bytes = seed_bytes_for(TEST_MNEMONIC_24)
    a = derive_password(seed_bytes, label="gmail")
    b = derive_password(seed_bytes, label="  GMAIL ")
    assert a.password == b.password


def test_different_seed_gives_different_password():
    a = derive_password(seed_bytes_for(TEST_MNEMONIC_24), label="gmail")
    b = derive_password(seed_bytes_for(TEST_MNEMONIC_24, passphrase="extra"), label="gmail")
    assert a.password != b.password
    assert a.base_index == b.base_index      # index is seed-independent
    assert a.fingerprint != b.fingerprint


def test_rotation_changes_the_password():
    seed_bytes = seed_bytes_for(TEST_MNEMONIC_24)
    a = derive_password(seed_bytes, label="gmail", counter=0)
    b = derive_password(seed_bytes, label="gmail", counter=1)
    assert a.password != b.password


def test_index_mode_ignores_label_and_counter():
    result = derive_password(seed_bytes_for(TEST_MNEMONIC_24), index=42)
    assert result.index == 42
    assert result.label == ""
    assert result.is_label_mode is False
    assert result.walk_steps == 0


@pytest.mark.parametrize("bad_index", [-1, 2**31, 2**32])
def test_out_of_range_index_rejected(bad_index):
    with pytest.raises(SeedPassError):
        derive_password(seed_bytes_for(TEST_MNEMONIC_24), index=bad_index)


def test_requires_label_or_index():
    with pytest.raises(SeedPassError):
        derive_password(seed_bytes_for(TEST_MNEMONIC_24))


# ---------------------------------------------------------------- the policy walk

def test_walk_is_deterministic(monkeypatch):
    """
    A real charset-policy miss happens about once in 1,000 short derivations,
    so we force one: reject every candidate until the index has advanced twice.
    """
    real = seedpass.satisfies_charset_policy
    seen = []

    def picky(password):
        seen.append(password)
        return len(seen) > 2 and real(password)

    monkeypatch.setattr(seedpass, "satisfies_charset_policy", picky)

    seed_bytes = seed_bytes_for(TEST_MNEMONIC_24)
    result = derive_password(seed_bytes, label="gmail")

    assert result.walk_steps == 2
    assert result.index == result.base_index + 2

    # Re-deriving without the patch at that index gives the same password
    monkeypatch.setattr(seedpass, "satisfies_charset_policy", real)
    assert derive_password(seed_bytes, index=result.index).password == result.password


def test_walk_gives_up_loudly(monkeypatch):
    monkeypatch.setattr(seedpass, "satisfies_charset_policy", lambda password: False)
    with pytest.raises(SeedPassError, match="charset policy"):
        derive_password(seed_bytes_for(TEST_MNEMONIC_24), label="gmail")


def test_index_mode_does_not_walk(monkeypatch):
    """Index mode stays bit-for-bit interoperable with other BIP-85 tools."""
    monkeypatch.setattr(seedpass, "satisfies_charset_policy", lambda password: False)
    result = derive_password(seed_bytes_for(TEST_MNEMONIC_24), index=3)
    assert result.index == 3
    assert result.walk_steps == 0


# ---------------------------------------------------------------- QR payloads

def test_secret_uri_round_trips():
    result = derive_password(seed_bytes_for(TEST_MNEMONIC_24), label="my bank")
    parsed = parse_uri(result.to_uri(include_secret=True))

    assert parsed["kind"] == "secret"
    assert parsed["label"] == "my bank"
    assert parsed["idx"] == result.index
    assert parsed["ctr"] == result.counter
    assert parsed["fmt"] == PasswordFormat.FULL
    assert parsed["fp"] == result.fingerprint
    assert parsed["secret"] == result.password


def test_uri_records_the_short_format():
    result = derive_password(seed_bytes_for(TEST_MNEMONIC_24), label="gmail",
                             fmt=PasswordFormat.SHORT)
    parsed = parse_uri(result.to_uri())
    assert parsed["fmt"] == PasswordFormat.SHORT
    assert len(parsed["secret"]) == 16


def test_reference_uri_omits_the_secret():
    result = derive_password(seed_bytes_for(TEST_MNEMONIC_24), label="gmail")
    uri = result.to_uri(include_secret=False)

    assert "secret=" not in uri
    assert result.password not in uri
    assert parse_uri(uri)["kind"] == "ref"


def test_uri_rejects_foreign_payloads():
    with pytest.raises(SeedPassError):
        parse_uri("bitcoin:bc1qexample")
