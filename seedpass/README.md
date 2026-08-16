# SeedPass — deterministic passwords on SeedSigner

Turns a SeedSigner into an air-gapped password generator. Load a BIP-39 seed the
way you already do, type a service name on the joystick keyboard, and the device
derives a base58 password — displayed on screen, or exported as a QR for a
companion app to store.

```
6w8BYxxBW7nx2s9qJkFxn6jGh69GYJYhoJm5W2tfGa1v!2   full,  46 chars, 256 bits
vugQwXTAY2wMna!2                                 short, 16 chars,  82 bits
```

**This repository is the Raspberry Pi / SeedSigner side only.** The phone /
tablet / PC vault app is not built. `SPEC.md` defines exactly what that app must
implement to interoperate.

Nothing is ever written to the MicroSD card. Passwords exist only on screen and
in the exported QR.

---

## The device

The Home menu keeps SeedSigner's native 2x2 grid:

| | |
|---|---|
| **New seed** | Generate a fresh seed from camera entropy, exactly as SeedSigner does |
| **Scan** | Scan a seed QR (SeedQR, CompactSeedQR, mnemonic QR) |
| **Seeds** | The in-memory seed list |
| **Settings** | SeedSigner's settings, unchanged |

Once a seed is loaded, its menu offers password derivation plus **Backup seed** —
SeedSigner's own seed-words / SeedQR export, untouched — and **Discard seed**.

The first three paths all end in the same place: pick or create a seed, then
derive passwords from it.

This is a password-only build. Installing SeedPass **replaces** the Home menu,
which removes access to SeedSigner's Tools menu, PSBT signing, address explorer
and message signing. Settings is left in place. See
[Trade-offs](#trade-offs) below.

---

## How it works

The derivation is plain [BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki),
application `128169'` — the raw-entropy ("HEX") application:

```
your seed → BIP-39 seed bytes → BIP-32 xprv
          → m/83696968'/128169'/{32 or 16}'/{index}'
          → raw entropy → big-endian integer
          → fixed-width base58 + "!2" = the password
```

No BIP-39 wordlist is involved in the password. The *parent* seed is still a
BIP-39 mnemonic — only the output changed.

| Format | Length | Bits | Example |
|---|---|---|---|
| **Full** (default) | 46 chars | 256 | `6w8BYxxBW7nx2s9qJkFxn6jGh69GYJYhoJm5W2tfGa1v!2` |
| **Short** | 16 chars | 82 | `vugQwXTAY2wMna!2` |

Length is fixed per format — no variance to manage. The two are **independent
derivations** (`num_bytes` is a BIP-85 path level), so compromise of a short
password leaks nothing about the full one for the same site.

**Why base58.** Bitcoin's alphabet omits `0`, `O`, `I` and `l` — the glyph pairs
that make a hand-transcribed password silently wrong. That costs 5.858 bits per
character against base64's 6, and buys legibility on a 240×240 screen. It is the
same idea as a password manager's "avoid ambiguous characters" toggle, except
baked in rather than optional.

Encoding is fixed width, not the variable-length form used for addresses: the
entropy integer is written as exactly 44 (or 14) digits, left-padded with the
alphabet's zero digit `1`. For the full format `58^44 > 2^256`, so nothing is
lost and a companion app can decode a scanned password straight back to the
BIP-85 entropy to verify it.

**Site rules.** The `!2` guarantees a digit and a symbol. Uppercase and lowercase
are guaranteed by the index walk rather than by mangling the encoding — forcing a
capital would corrupt the base58 and silently discard entropy. The walk fires for
about one label in a thousand at the short format, and essentially never at the
full one.

**The 16-char option** is there for sites that cap password length. Sixteen
characters physically cannot hold 256 bits — 14 base58 digits carry 82. For
scale, that is above Apple's generated-password entropy and about level with a
mainstream password manager's default, so it is weak only next to the full
format. Use it where a site forces you to, not by preference.

**How the index is chosen.** Rather than making you track index numbers, it's
derived from the service name:

```
base_index = HMAC-SHA256("SeedPass/v1/index", normalized_label ‖ 0x00 ‖ counter)[0:4] & 0x7FFFFFFF
```

So typing `my bank` always regenerates the same password. Names are normalized
(NFKD → casefold → whitespace collapsed), so `Gmail`, `GMAIL` and ` gmail ` all
match. The counter is the rotation lever: bump it to re-issue a password for the
same name.

You can also derive straight from a raw BIP-85 index if you'd rather manage
indices yourself. Index mode skips the walk, so it stays bit-for-bit
interoperable with other BIP-85 tools.

Full details, including the QR payload grammar and the security limitations, are
in [`SPEC.md`](SPEC.md).

---

## Installing

SeedPass adds three new modules and makes two edits to existing SeedSigner
files. `install.py` does both, and is safe to re-run.

Built and tested against SeedSigner `0.8.7` (commit `5088588`, Aug 2026).

### Option A — patch the device over SSH

```bash
# from your computer
scp -r seedpass pi@seedsigner.local:/tmp/

# on the device
ssh pi@seedsigner.local
sudo python3 /tmp/seedpass/install.py /opt/seedsigner
sudo systemctl restart seedsigner    # or just power-cycle
```

SeedSigner's release images are hardened and may have SSH disabled — in that
case use Option B.

### Option B — build a card from source (recommended)

Follow SeedSigner's own
[Raspberry Pi OS build instructions](https://github.com/SeedSigner/seedsigner/blob/main/docs/raspberry_pi_os_build_instructions.md)
up to the point where the SeedSigner source is cloned onto the card, then apply
SeedPass before the first boot:

```bash
git clone https://github.com/SeedSigner/seedsigner.git
cd seedsigner
git checkout 0.8.7

python3 /path/to/seedpass/install.py .
```

Continue with the rest of SeedSigner's instructions as normal. No extra Python
dependencies are needed — SeedPass uses `embit`, which SeedSigner already
requires.

### Option C — mount the card and patch it directly

```bash
sudo python3 install.py /media/you/rootfs/opt/seedsigner
```

### Uninstalling

```bash
python3 install.py /opt/seedsigner --revert
```

This restores the patched files to their original text and removes the new
modules, giving you a stock SeedSigner back. Verified to produce a clean git
tree.

### What the installer changes

New files:

```
src/seedsigner/models/seedpass.py                derivation logic (no GUI)
src/seedsigner/gui/screens/seedpass_screens.py   screens
src/seedsigner/views/seedpass_views.py           the flow
tests/test_seedpass.py                           unit tests
tests/test_flows_seedpass.py                     flow tests
```

Replaced files (the original is kept as `<name>.seedpass-original` and put back
by `--revert`):

```
src/seedsigner/resources/img/logo_black_240.png  the boot splash
```

The splash logo is a SeedPass version of SeedSigner's pill mark: same orange,
same 218x70 wordmark box, same vertical centring. Those dimensions matter --
`views/screensaver.py` positions the version string beneath the logo assuming it
is 70px tall and centred.

`LogoScreen` loads this one file, and **both** `OpeningSplashScreen` (boot) and
`ScreensaverScreen` (the bouncing idle logo) inherit from it, so replacing it
changes both.

It is deliberately a fully opaque image rather than a transparent one, exactly
as SeedSigner's is. The splash fades the logo in with
`self.logo.putalpha(255 - i)`, which replaces the *entire* alpha channel with a
single value; any per-pixel transparency is destroyed, so anti-aliased edges
would render at full strength and look jagged. Baking the anti-aliasing into RGB
against black avoids that. The screensaver has the same requirement from the
other direction: it pastes the logo with no alpha mask. Regenerate it with
`python3 tools/make_logo.py src/seedsigner/resources/img/logo_black_240.png`
from the SeedSigner repo root if you want to change the wording.

Edits to existing files:

- `views/view.py` — replaces `MainMenuView`'s entries with New seed / Scan /
  Seeds / Settings. Four entries means `MainMenuScreen` still works;
  `LargeButtonScreen` raises on anything but exactly 2 or 4 buttons.
- `views/seed_views.py` — `SeedOptionsView` redirects into the password flow.
  Every seed-loading path in SeedSigner finalizes there, so one redirect catches
  photo entropy, QR scan, manual entry and the seed list alike.

If the installer reports that it can't find an anchor, your SeedSigner version
differs from the one this was built against; the edits are short enough to apply
by hand from `install.py`'s `PATCHES` list.

---

## Using it

1. **Get a seed in memory** — New seed, Scan, or Seeds.
2. **New / lookup by name** — type the service (lowercase, digits, `.`, `-`,
   space). Or **By BIP-85 index** for raw index entry.
3. **First password** or **Rotate** — rotate if you're re-issuing a password for
   a name you've used before.
4. **Review** shows the service, the resolved BIP-85 index, the format and the
   parent seed's fingerprint. Nothing secret yet. **Change format** here to
   switch to the 16-char short form.
5. **Reveal password** → dire warning → the password in groups (5 groups of 10
   for the full format, 2 groups of 8 for the short one). **The groups are
   display only — type it as one string, no spaces.**
6. **Export** — a QR containing the password, a QR containing only the name and
   index (no secret), or Done.

**Backup seed** on the password menu is SeedSigner's own backup flow, unchanged:
view the seed words, or export the seed as a SeedQR (standard or compact) to
transcribe. That is how you back up the seed that every password derives from —
back it up the same way you would any SeedSigner seed. Its "Done" routes back to
the password menu.

Re-entering the same name and format on the same seed always reproduces the same
password, so this doubles as the lookup path.

**Discard seed** wipes the seed from memory.

Note the asymmetry: passwords are derived and never stored, so they need no
backup. The *seed* is the only thing that needs backing up — lose it and every
password is gone.

---

## Verifying off-device

`tools/seedpass_derive.py` is a reference CLI that imports the exact same module
the device runs, so you can confirm the device's output or recover a password
without it:

```bash
pip install embit

# which index does a name map to? (no seed required)
python3 tools/seedpass_derive.py --label gmail --index-only

# derive (prompts for the seed, hidden input)
python3 tools/seedpass_derive.py --label "my bank"
python3 tools/seedpass_derive.py --label "my bank" --counter 1
python3 tools/seedpass_derive.py --label gmail --format b58-16
python3 tools/seedpass_derive.py --index 42
```

It asks for your seed phrase. Only run it on a machine you'd be willing to type
a seed into.

---

## Tests

```bash
cd /path/to/seedsigner
pip install -e .
pip install -r tests/requirements.txt
cd tests
python3 -m pytest test_seedpass.py test_flows_seedpass.py -v
```

86 tests: derivation against the official BIP-85 HEX vector, the fixed-width
base58 codec and its round-trip, the absence of ambiguous glyphs in every
generated password, fixed lengths per format, that the full format preserves all
256 bits while the short one is deliberately lossy, that the two formats sit at
different path levels, the charset policy and its index walk (determinism, that
it gives up loudly, that index mode never walks), label normalization and
rejection, rotation, QR payload round-trips, and headless flow tests covering the
Home menu, every seed-entry path, display chunking for both formats, format
switching, both derivation modes, both export types, invalid input, seed discard,
SeedQR export (standard and compact) with its return path, and the Electrum-seed
guard.

---

## Trade-offs

**base58 removes glyph ambiguity but not error detection.** There is no `0`/`O`
or `l`/`I` confusion left to make, which was the main hazard. But a *dropped or
transposed* character still produces a silently wrong password: unlike a BIP-39
mnemonic, there is no checksum to catch it. Scanning the QR sidesteps this
completely. The display mitigates what it can — monospace, short groups, an
explicit "no spaces, case matters" note.

**Replacing the Home menu removes the bitcoin-signing side of the device**: PSBT
signing, the address explorer, message signing and the Tools menu. Settings is
retained, so dire warnings, persistent settings, display rotation, language and
the hardware I/O test all still work.

SeedSigner's own test suite reflects the removals: 16 of its tests now fail, all
of them exercising features no longer reachable. (Nine further failures in
`test_l10n.py` and `test_seedqr.py` pre-date this work and fail identically on a
clean checkout — they need compiled translation catalogs and SeedSigner's forked
`pyzbar`.) The seed-loading, settings, controller and BIP-85 tests all pass.

---

## Before you rely on this

Read section 4 of `SPEC.md`. The short version:

- Your seed is now a single point of compromise for your passwords **and** any
  bitcoin it secures. Strongly consider a dedicated seed, or a distinct BIP-39
  passphrase, so the two roles don't share a secret.
- Rotation is manual. If a site is breached you must bump the counter *and*
  change the password at the site; the old one stays valid at the old index.
- You have to remember the exact service names you used, and which format.
- The `!2` is public and adds no entropy; security rests on the 256 (or 82) bits.
- The short format is 82 bits, not 256. Use it only where a site forces it, and
  remember which sites those are — the two formats are different passwords.
- A site that bans `!`, or caps below 16 characters, still can't take these.
- This has not been audited, and it has not been run on physical hardware.

## Status

The derivation core and the view routing are covered by 86 passing automated
tests. What hasn't happened is a run on a real Pi Zero: layout on the 240×240
screen is calculated from SeedSigner's own layout constants but not visually
confirmed. The password screen auto-sizes its font to fit both the widest group
and the available height, which matters most for the 46-char full format; verify
it before relying on it. SeedSigner's screenshot generator (`tests/screenshot_generator`)
is the fastest way to check layout without flashing a card.
