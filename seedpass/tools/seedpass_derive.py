#!/usr/bin/env python3
"""
seedpass_derive.py — reference implementation of the SeedPass derivation.

Runs anywhere Python and `embit` are available, so you can verify that the
device produced the right password (or recover a password if the device is
lost). Depends only on `embit`:

    pip install embit

Examples:

    # Derive by service name
    python3 seedpass_derive.py --label "my bank"

    # Rotate an existing password
    python3 seedpass_derive.py --label "my bank" --counter 1

    # Derive by raw BIP-85 index (interoperable with any BIP-85 tool)
    python3 seedpass_derive.py --index 42

    # 16-char form, for sites that cap password length
    python3 seedpass_derive.py --label gmail --format b58-16

    # Just show which BIP-85 index a name maps to (no seed needed)
    python3 seedpass_derive.py --label gmail --index-only

SECURITY WARNING
----------------
This script asks for your seed phrase. Only run it on a machine you would be
willing to type your seed into — ideally an offline one. The device flow exists
precisely so you don't have to do this.
"""
import argparse
import getpass
import sys

# Import the same module the device uses, so there is exactly one
# implementation of the derivation rules.
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent / "src"))

from seedsigner.models.seedpass import (  # noqa: E402
    DEFAULT_FORMAT,
    PasswordFormat,
    SeedPassError,
    derive_password,
    index_from_label,
    normalize_label,
)


def read_mnemonic(args) -> str:
    if args.mnemonic:
        return args.mnemonic
    print("Enter your BIP-39 mnemonic (input hidden):", file=sys.stderr)
    return getpass.getpass("mnemonic: ")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reference implementation of SeedPass password derivation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--label", help='Service name, e.g. "my bank"')
    source.add_argument("--index", type=int, help="Raw BIP-85 child index")

    parser.add_argument("--counter", type=int, default=0,
                        help="Rotation counter for --label (default: 0)")
    parser.add_argument("--format", dest="fmt", default=DEFAULT_FORMAT,
                        choices=PasswordFormat.ALL,
                        help=f"Password shape (default: {DEFAULT_FORMAT})")
    parser.add_argument("--passphrase", default="",
                        help="Optional BIP-39 passphrase on the parent seed")
    parser.add_argument("--mnemonic",
                        help="Seed phrase (omit to be prompted; safer)")
    parser.add_argument("--index-only", action="store_true",
                        help="Print the BIP-85 index for --label and exit; no seed needed")
    parser.add_argument("--uri", action="store_true",
                        help="Also print the seedpass:// export payload")

    args = parser.parse_args()

    try:
        if args.index_only:
            if args.label is None:
                parser.error("--index-only requires --label")
            print(f"label:  {normalize_label(args.label)}")
            print(f"index:  {index_from_label(args.label, args.counter)}")
            return 0

        from embit import bip39
        mnemonic = " ".join(read_mnemonic(args).split())
        if not bip39.mnemonic_is_valid(mnemonic):
            print("error: not a valid BIP-39 mnemonic", file=sys.stderr)
            return 2

        seed_bytes = bip39.mnemonic_to_seed(mnemonic, password=args.passphrase)

        result = derive_password(
            seed_bytes=seed_bytes,
            label=args.label,
            index=args.index,
            counter=args.counter,
            fmt=args.fmt,
        )

    except SeedPassError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    print(f"seed fingerprint: {result.fingerprint}")
    if result.label:
        print(f"label:            {result.label}")
        print(f"counter:          {result.counter}")
    if result.walk_steps:
        print(f"index walk:       +{result.walk_steps} (from {result.base_index}, for the charset policy)")
    print(f"derivation:       {result.derivation_path}")
    print(f"format:           {result.fmt}  ({result.num_bits} bits)")
    print()
    print(f"password:         {result.password}")
    print(f"                  ({result.char_length} chars)")
    if args.uri:
        print()
        print(result.to_uri(include_secret=True))

    return 0


if __name__ == "__main__":
    sys.exit(main())
