# SeedPass Specification v1

This document defines the derivation and export formats implemented by the
SeedSigner-side software. It is the contract that a companion app (phone /
tablet / PC) must follow to interoperate.

Everything here is deterministic. Given the same seed and the same inputs, any
correct implementation produces byte-identical output.

Reference implementations:
- `src/seedsigner/models/seedpass.py` (the device)
- `tools/seedpass_derive.py` (off-device CLI, same module)

---

## 1. Derivation chain

```
BIP-39 mnemonic (12 or 24 words) + optional BIP-39 passphrase
  └─ BIP-39 seed bytes (512 bits, PBKDF2-HMAC-SHA512, 2048 rounds)
       └─ BIP-32 master key (xprv, mainnet version bytes)
            └─ BIP-85 application 128169' ("HEX") at
                 m/83696968'/128169'/{num_bytes}'/{index}'
                 └─ raw entropy, 32 or 16 bytes
                      └─ big-endian integer
                           └─ fixed-width base58 (Bitcoin alphabet)
                                └─ "!2" appended == the password
```

The BIP-85 part is unmodified
[BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki),
application number `128169'` — the raw-entropy ("HEX") application. No BIP-39
wordlist is involved in the password. The *parent* seed is still a BIP-39
mnemonic; only the derived output changed.

All four path levels are hardened. Per BIP-85, the derived key's `secret`
(32 bytes) is run through `HMAC-SHA512(key="bip-entropy-from-k", msg=secret)`,
and the first `num_bytes` of that digest are the entropy.

**Mainnet version bytes are always used** when constructing the BIP-32 root,
regardless of the device's network setting. The network setting affects only how
the fingerprint is displayed, never the derived password.

### 1.1 Formats

| `fmt` | `num_bytes` | base58 chars | Total length | Effective bits |
|---|---|---|---|---|
| `b58-256` (default) | 32 | 44 | **46** | **256** |
| `b58-16` | 16 | 14 | **16** | **82** |

Length is fixed for a given format — there is no length variance to manage.

`b58-16` exists only for sites that cap passwords at 16 characters. Sixteen
characters cannot hold 256 bits: 14 base58 digits carry
`14 × log2(58) ≈ 82` bits, and the two-character suffix carries none. It is a
genuinely weaker password and MUST be presented as such. For calibration, 82
bits is still above Apple's generated-password entropy and roughly level with a
mainstream password manager's default, so it is weak only relative to
`b58-256`.

The two formats are **independent derivations**: `num_bytes` is a BIP-85 path
level, so `b58-256` and `b58-16` for the same label produce unrelated values.
Compromise of a short password leaks nothing about the full one.

### 1.2 Encoding

Bitcoin's base58 alphabet, in this exact order:

```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

It omits `0`, `O`, `I` and `l` — the glyph pairs that make a hand-transcribed
password silently wrong. That is the whole reason for choosing it over base64url,
and it costs only 5.858 bits per character against 6.

Encoding is **fixed width**, not the variable-length form used for Bitcoin
addresses. The integer `int.from_bytes(entropy, "big")` is written as exactly
`num_b58_chars` digits, most significant first, left-padded with the alphabet's
zero digit `1`. There is no leading-zero-byte special case.

```
value = int.from_bytes(entropy, "big")
digits = []
for _ in range(num_b58_chars):
    value, remainder = divmod(value, 58)
    digits.append(ALPHABET[remainder])
encoded = "".join(reversed(digits))
```

Consequently the encoding is `value mod 58**num_b58_chars`:

- For `b58-256`, `58**44 ≈ 2**257.8 > 2**256`, so nothing is discarded and the
  password decodes back to the exact 32 entropy bytes.
- For `b58-16`, `58**14 = 2**82 < 2**128`, so the high bits of the 16-byte source
  are discarded by design. The source entropy is **not** recoverable from a short
  password.

Then the literal suffix `!2` is appended:

```
entropy:  58 27 eb 3f ... (32 bytes)
password: 6w8BYxxBW7nx2s9qJkFxn6jGh69GYJYhoJm5W2tfGa1v!2
```

**The suffix is part of the password, not presentation.** The value shown on the
device screen, the value in the export QR, and the value a companion app stores
are one and the same string. Implementations MUST NOT append it at export time
only.

Strip the suffix, re-pad to a multiple of four with `=`, and the remainder
decodes back to the exact BIP-85 entropy. A companion app can use this to verify
a scanned password against its own derivation.

### 1.3 Character-class policy

Many sites demand an uppercase letter, a lowercase letter, a digit and a symbol.

- **Digit and symbol** are guaranteed by the `!2` suffix.
- **Uppercase and lowercase** are guaranteed by the index walk in §2.3.

The first character is deliberately *not* force-capitalized. Uppercasing a
base58 character would corrupt the encoding, break the decode-back property, and
silently discard entropy.

### 1.4 BIP-85 test vector

Implementations MUST reproduce the HEX vector from the BIP-85 text. With master
key
`xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb`
at `m/83696968'/128169'/64'/0'`:

```
492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f8785
55d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c
```

---

## 2. Choosing the index

There are two modes. Both end at the same BIP-85 derivation; they differ in
where `{index}` comes from and whether the charset policy is enforced.

### 2.1 Index mode (advanced)

The user supplies `{index}` directly. Valid range `0 .. 2^31 - 1`. No label is
associated with the result, and **the policy walk is not applied** — the caller
asked for a specific BIP-85 index and gets exactly that, so index mode stays
bit-for-bit interoperable with any other BIP-85 tool.

### 2.2 Label mode (default)

The index is derived from a service name, so the name alone is enough to
regenerate the password — there is no index list to back up.

**Label normalization** (MUST be applied before anything else):

1. Unicode NFKD normalization.
2. `str.casefold()`.
3. Collapse all runs of whitespace (including tabs and newlines) to a single
   ASCII space, and strip leading/trailing whitespace.
4. Reject if the result is empty or longer than 64 characters.
5. Reject if any character is outside the allowed set:
   `a-z`, `0-9`, space, and `. - _ + @ : /`

Normalization is idempotent: `normalize(normalize(x)) == normalize(x)`.

So `"Gmail"`, `"  GMAIL  "` and `"gmail"` all normalize to `gmail`. `"café!"` is
rejected (the `!` survives NFKD).

**Base index derivation:**

```
counter    ∈ 0 .. 999
message    = utf8(normalized_label) || 0x00 || ascii(decimal(counter))
digest     = HMAC-SHA256(key = "SeedPass/v1/index", msg = message)
base_index = int_from_bytes(digest[0:4], byteorder="big") & 0x7FFFFFFF
```

The HMAC key is a fixed public constant used purely for domain separation. The
index is **not** a secret and is **seed-independent** — a companion app can show
which index a label maps to without ever holding the seed. All secrecy comes
from the seed.

Note that `base_index` does not depend on the format: the same label yields
the same index for both `b58-256` and `b58-16`.

Collision probability is negligible at realistic vault sizes (~50% at ~54,000
entries in a 2^31 space; ~0.1% at 2,000 entries). Two labels that did collide
would produce the same password, not a failure.

**The counter is the rotation mechanism.** To change a password without changing
the service name, increment the counter. `counter=0` is the first password.

### 2.3 The policy walk (label mode only)

If a candidate password has no uppercase letter, or no lowercase letter, the
index steps forward and we try again:

```
for step in 0, 1, 2, ...:
    index    = (base_index + step) & 0x7FFFFFFF
    password = b58_fixed(bip85_hex(seed, num_bytes, index)) + "!2"
    if has_upper(password) and has_lower(password):
        return password, index, step
```

This is fully deterministic, so the label alone still regenerates the password.

It rarely fires. The alphabet holds 24 uppercase, 25 lowercase and 9 digit
characters, so for the 14-character short format the chance of a miss is
`(34/58)^14 + (33/58)^14 ≈ 0.09%` — about one label in a thousand. For the
44-character full format it is negligible. The implementation caps the walk at
1000 attempts before raising, a bound unreachable in practice.

The exported QR carries the **final** index, so an app never has to replay the
walk.

---

## 3. Export QR payloads

Two payload types, both plain UTF-8 text in a static (non-animated) QR.

### 3.1 Grammar

```
seedpass://v1/secret?fp=<fp>&idx=<idx>&ctr=<ctr>&fmt=<fmt>[&label=<label>]&secret=<secret>
seedpass://v1/ref?fp=<fp>&idx=<idx>&ctr=<ctr>&fmt=<fmt>[&label=<label>]
```

| Field | Meaning |
|---|---|
| `fp` | 8 lowercase hex chars: BIP-32 master fingerprint of the **parent** seed |
| `idx` | decimal BIP-85 child index **actually used**, i.e. after any walk |
| `ctr` | decimal rotation counter (`0` in index mode) |
| `fmt` | `b58-256` or `b58-16` |
| `label` | percent-encoded normalized label; **omitted entirely** in index mode |
| `secret` | percent-encoded password; present only in the `secret` variant |

Parameters appear in the order shown. Percent-encoding is applied to every
character that is not unreserved (`safe=""`); in particular `!` becomes `%21`,
so a password ending `!2` appears as `%212`.

- The **`secret`** payload carries the password itself. This is what a vault app
  scans to store a credential.
- The **`ref`** payload carries no secret at all. It lets an app record that a
  credential exists — its name, index and strength — without ever handling the
  password.

`fp` lets the app warn when a scanned credential belongs to a different seed
than the vault was set up with. `fmt` is required to re-derive, since the two
formats sit at different path levels.

Because `fmt` and `idx` are both present, an app that holds the seed can
re-derive the password directly, with no knowledge of the walk.

### 3.2 Parsing rules

Implementations MUST reject a payload that does not begin with
`seedpass://v1/secret?` or `seedpass://v1/ref?`. Unknown query parameters SHOULD
be ignored so that future minor additions do not break older parsers. A breaking
change bumps the `v1` segment.

### 3.3 QR size

A `b58-256` secret payload is about 150 characters — a version-7 QR (45×45
modules), comfortable on the 240×240 display. `b58-16` is much smaller, and the
`ref` payload smaller still.

---

## 4. Security properties and limits

**What this gives you.** One seed backs up every password. Passwords are never
stored anywhere — the device writes no part of a derivation to disk. Losing your
vault app costs you nothing but convenience; the seed regenerates everything.

**What it does not give you.**

- **The seed is a single point of compromise.** Anyone with the seed has every
  password *and* any bitcoin secured by that seed. Consider using a dedicated
  seed for passwords, or a distinct BIP-39 passphrase, so the two roles are
  separated.
- **The seed is also the single point of failure.** Passwords are derived, not
  stored, so there is nothing else to back up — and nothing else to fall back on.
  Back the seed up as a SeedQR or written words before you rely on any password
  derived from it. If the seed carries a BIP-39 passphrase, that must be backed
  up separately; the seed words alone will derive a different set of passwords.
- **base58 removes glyph ambiguity but not error detection.** There is no `0`
  versus `O` or `l` versus `I` confusion to make, which is the common
  transcription error. But a *dropped or transposed* character still produces a
  silently wrong password: unlike a BIP-39 mnemonic, there is no checksum.
  Scanning the QR avoids this entirely.
- **`b58-16` is 82 bits, not 256.** Use it only where a site forces it. It is not
  interchangeable with `b58-256` for the same label — they are different
  passwords at different path levels.
- **Rotation is manual.** If a site is breached, you must increment the counter
  *and* change the password at the site. The old password remains valid at the
  old index forever.
- **Labels must be remembered exactly.** `my bank`, `mybank` and `bank` are three
  different passwords, and the format must match too. The `ref` QR exists partly
  so an app can keep an authoritative list.
- **The suffix is public.** `!2` is a constant, contributes no entropy, and an
  attacker is assumed to know it. Security rests entirely on the 256 (or 82) bits.
- **Site rules can still defeat this.** The four common character classes are
  covered and `b58-16` handles the 16-character cap, but a site that bans `!`, or
  caps below 16 characters, still cannot take these passwords. base58 itself is
  alphanumeric, so no other character is at risk.
- **The screen is the weak point.** A derived password is only as private as the
  display it is shown on and whoever can see it.

---

## 5. Identities (SLIP-0013)

Separate from passwords in every way that matters. Passwords derive through
BIP-85 at `m/83696968'/128169'/...`; identities derive through
[SLIP-0013](https://github.com/satoshilabs/slips/blob/master/slip-0013.md) at
`m/13'/A'/B'/C'/D'`. Different purpose branches of one seed: they cannot
collide, and adding identities does not move a single password.

### 5.1 Derivation

Unmodified SLIP-0013:

```
hash    = sha256(uint32_le(index) || uri)
A,B,C,D = uint32_le  x4  from hash[0:16]
path    = m/13'/A'/B'/C'/D'      (each OR 0x80000000)
```

SLIP-0010 for secp256k1 is identical to BIP-32, so no separate derivation is
needed. The spec's worked example is a test:
`https://satoshi@bitcoin.org/login` at index 0 gives
`m/2147483661/2637750992/2845082444/3761103859/4005495825`.

### 5.2 Labels are URIs

There is one derivation, with two ways to name it:

| Named by | URI used |
|---|---|
| URI, e.g. `https://example.com` | itself |
| service name, e.g. `gmail` | `seedpass://gmail` |

`seedpass://gmail` is a valid RFC 3986 URI, so it goes through the standard
unchanged. Labels are normalized with the same rules as password labels, so
`Gmail` and `gmail` are one identity. **SLIP-0013's `index` is the rotation
counter**, so rotation comes from the spec rather than being bolted on.

Identities named by URI interoperate with any other SLIP-0013 implementation.
Identities named by label keep the same mental model as passwords.

### 5.3 Challenge-response

Per SLIP-0013, a service sends an identity plus two challenges: a *hidden* one
(random bytes, max 64) and a *visual* one (text, max 64, shown to the user). The
signer signs `sha256(hidden) || sha256(visual)` with Bitcoin message signing and
returns the signature with the public key. The service creates an account the
first time it sees a public key and logs the user in thereafter.

```
request   seedpass://v1/auth?id=<uri>&idx=<n>&h=<hex>&v=<text>
response  seedpass://v1/authresp?id=<uri>&idx=<n>&pk=<hex>&sig=<base64>
pubkey    seedpass://v1/pubkey?fp=<fp>&idx=<n>&id=<uri>&pk=<hex>&addr=<addr>
```

### 5.4 What this is not

**It is not FIDO2.** FIDO2 is phishing-proof because the *browser* supplies the
origin and the user cannot be fooled. Here, the URI and the visual challenge are
displayed on the SeedSigner screen and a human decides. That is a real
mitigation, and SLIP-0013 puts the visual challenge in the protocol precisely
for it -- but it is human verification, not a structural guarantee.

**No existing service accepts it.** A service must implement SLIP-0013
verification. The upside over a private scheme is that doing so also serves
Trezor users.

## 6. FIDO2 (USB CTAP2)

A third derivation branch, independent of passwords and identities. Credentials
are P-256 keys derived from the seed, served over USB HID to a browser.

### 6.1 Why P-256

WebAuthn's mandatory algorithm is ES256 -- ECDSA over P-256. secp256k1 has a
COSE identifier (-47) but effectively no browser support, so an authenticator
offering only it would be refused at registration.

This also separates FIDO2 from everything else structurally: a signature the
FIDO2 path produces **cannot** be a valid Bitcoin signature, whatever a host
persuades the device to sign. Different curve, not merely a different key.

Signing is RFC 6979 deterministic, so no RNG is involved -- a weak generator
would otherwise leak the private key through ECDSA signatures.

### 6.2 Stateless credentials

The device stores nothing, so credentials are derived and the credential ID
carries what is needed to re-derive:

```
credential id = nonce(16) || HMAC-SHA256(mac_key, rpIdHash || nonce)[:16]
key           = HMAC-SHA256(master, "key" || rpIdHash || nonce) -> P-256 scalar
master        = HMAC-SHA256("SeedPass/v1/fido2/master", seed)
```

The MAC is not decoration. Without it a host could invent a credential ID and
have the device sign with a key of its choosing -- a signing oracle over an
attacker-chosen path. It is verified in constant time before anything is
derived, and it binds the credential to its RP, so an ID issued for one site
fails at another.

Derivation is one-way HMAC rather than BIP-32 child derivation, so a leaked
credential key reveals nothing about the seed or sibling keys.

These are non-discoverable credentials: `rk` is reported false, and an assertion
without an allowList is refused. There is nothing to enumerate.

### 6.3 Sessions

The relying party is chosen before the cable, by scanning
`seedpass://v1/fido2?rp=<rpid>` produced by the companion app from the site URL.
The session then refuses every other RP for its lifetime.

**The seed is resident during a USB session.** An earlier design derived the
credential, dropped the seed, then connected -- but FIDO2 credentials are
permanent, so the key would have to survive a power cycle, and there is nowhere
to put it. The screen dies with the power, the SD card cannot be reliably erased
because of flash wear-levelling, and photographing the key makes a lasting copy
of a long-lived secret. The scheme required a second display that does not
exist.

So the position is the same as every hardware wallet, and the same as a YubiKey
whose secrets are present whenever it is plugged in. What arming buys is that a
host cannot enumerate sites, cannot mint credentials for domains the user never
approved, and cannot swap the RP mid-session.

`signCount` stays 0 -- the spec's "not supported" -- because a counter needs
somewhere to persist. The cost is that an RP cannot detect a cloned
authenticator by counter regression; cloning here means holding the seed, at
which point the counter is not the problem.

### 6.4 What is deliberately absent

No CTAP1/U2F (and NMSG is advertised so hosts do not try), no PIN protocol, no
credential management, no bio enrolment, no large blobs, no `authenticatorReset`
-- there is nothing stored to erase, and honouring it would imply a host could
wipe the seed. Each omission is code an attacker cannot reach.

### 6.5 Residual exposure

A bug in the CTAP stack reaches the seed. The stack is small and strict, and
user presence is required before any key is touched, but it is the first input
channel on this device an attacker can drive directly rather than one a user
chooses to scan.

A malicious *application* on the host can also claim any RP ID. That is inherent
to CTAP -- the browser is trusted to supply it -- and is why the RP is displayed
for approval before signing.

## 7. Version history

**v1** — passwords: BIP-85 app 128169' raw entropy, fixed-width Bitcoin base58
with a `!2` suffix, two formats (`b58-256` at 256 bits and `b58-16` at 82 bits for
length-capped sites), HMAC-SHA256 label indexing, deterministic index walk for
the charset policy, `seedpass://v1/` payloads. Identities: SLIP-0013 at `m/13'`,
with labels expressed as `seedpass://<label>` URIs.
