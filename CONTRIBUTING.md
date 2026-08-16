# Working on SeedPass

## Running the tests

The tests live with the payload but run against a patched SeedSigner checkout,
because that is what they are testing:

```bash
git clone https://github.com/SeedSigner/seedsigner.git
cd seedsigner
git checkout 5088588dd4f913a489329d2422b0f925ed281856
pip install -r requirements.txt

python3 /path/to/seedpass-os/seedpass/install.py .
cd tests && python3 -m pytest test_seedpass.py test_seedpass_identity.py \
    test_fido2.py test_sido3.py test_flows_seedpass.py -q
```

309 tests should pass. When finished:

```bash
python3 /path/to/seedpass-os/seedpass/install.py . --revert
git status --porcelain    # must be empty
```

A revert that does not leave the tree clean is a bug in `install.py`.

## The rule that matters most

**Adding anything must not move an existing derivation.** Passwords, identities
and FIDO2 credentials come from independent branches of one seed, and someone
depends on those outputs staying the same forever.

`test_fido2.py::test_fido2_does_not_disturb_passwords_or_identities` asserts
literal expected values for this reason. If that test fails, the change is
wrong -- do not update the expected values to match.

## The version pin

`install.py` patches SeedSigner at commit `5088588dd4f9` by matching exact lines
of upstream code. It targets a commit rather than the 0.8.7 tag because
SeedSigner refactored its seed views from `seed_num: int` to `seed: Seed`
between them.

Moving to a newer upstream means re-checking every anchor in `PATCHES`. The
installer validates all of them before modifying anything, so a mismatch fails
cleanly rather than half-patching the tree.

## Style

Comments should explain why, not what. Several here record a wrong turn -- the
FIDO2 key-export scheme that could not work, the public-suffix list that missed
`co.uk` -- so the same ground is not covered twice.
