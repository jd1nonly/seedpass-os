#!/usr/bin/env python3
"""
Install SeedPass into a SeedSigner source tree.

Copies three new modules in and makes two idempotent edits to existing
SeedSigner files:

  1. Replaces the Home menu with New seed (photo entropy), Scan, Seeds and
     Settings, turning the device into a password-only tool.
  2. Makes SeedOptionsView redirect into the password flow, so every path that
     loads a seed (photo, scan, manual entry, the seed list) ends up in the same
     place.

Usage (run from anywhere):

    python3 install.py /path/to/seedsigner
    python3 install.py /path/to/seedsigner --revert

On the device itself, SeedSigner lives at /opt/seedsigner:

    sudo python3 install.py /opt/seedsigner

Re-running is safe: already-applied edits are detected and skipped.
"""
import argparse
import shutil
import sys

from pathlib import Path


# The SeedSigner app commit SeedPass was developed and tested against. Not the
# 0.8.7 tag -- see the anchor error message below for why.
TESTED_COMMIT = "5088588dd4f913a489329d2422b0f925ed281856"

NEW_FILES = [
    "src/seedsigner/models/seedpass.py",
    "src/seedsigner/models/seedpass_identity.py",
    "src/seedsigner/models/p256.py",
    "src/seedsigner/models/fido2_cbor.py",
    "src/seedsigner/models/fido2_credential.py",
    "src/seedsigner/models/fido2_ctaphid.py",
    "src/seedsigner/models/fido2_authenticator.py",
    "src/seedsigner/models/fido2_session.py",
    "src/seedsigner/models/fido2_transport.py",
    "src/seedsigner/models/sido3.py",
    "src/seedsigner/views/seedpass_scan_views.py",
    "src/seedsigner/gui/screens/seedpass_screens.py",
    "src/seedsigner/views/seedpass_views.py",
]

# Files that already exist upstream and get replaced. The original is kept
# alongside so --revert can put it back exactly.
REPLACED_FILES = [
    "src/seedsigner/resources/img/logo_black_240.png",
]

BACKUP_SUFFIX = ".seedpass-original"

TEST_FILES = [
    ("tests/test_seedpass.py", "tests/test_seedpass.py"),
    ("tests/test_seedpass_identity.py", "tests/test_seedpass_identity.py"),
    ("tests/test_fido2.py", "tests/test_fido2.py"),
    ("tests/test_sido3.py", "tests/test_sido3.py"),
    ("tests/test_flows_seedpass.py", "tests/test_flows_seedpass.py"),
]


# --------------------------------------------------------------------------- #
# Patch 1: the Home menu.
#
# MainMenuScreen is a LargeButtonScreen, which raises on anything but exactly 2
# or 4 buttons -- so four entries keeps SeedSigner's native 2x2 home grid and its
# power button. Dropping to three would require switching to a ButtonListScreen.
# --------------------------------------------------------------------------- #

MAIN_MENU_ORIGINAL = '''class MainMenuView(View):
    SCAN = ButtonOption("Scan", SeedSignerIconConstants.SCAN)
    SEEDS = ButtonOption("Seeds", SeedSignerIconConstants.SEEDS)
    TOOLS = ButtonOption("Tools", SeedSignerIconConstants.TOOLS)
    SETTINGS = ButtonOption("Settings", SeedSignerIconConstants.SETTINGS)

    def run(self):
        from seedsigner.gui.screens.screen import MainMenuScreen
        button_data = [self.SCAN, self.SEEDS, self.TOOLS, self.SETTINGS]
        selected_menu_num = self.run_screen(
            MainMenuScreen,
            title=_("Home"),
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__POWER_BUTTON:
            return Destination(PowerOptionsView)

        if button_data[selected_menu_num] == self.SCAN:
            from seedsigner.views.scan_views import ScanView
            return Destination(ScanView)
       \x20
        elif button_data[selected_menu_num] == self.SEEDS:
            from seedsigner.views.seed_views import SeedsMenuView
            return Destination(SeedsMenuView)

        elif button_data[selected_menu_num] == self.TOOLS:
            from seedsigner.views.tools_views import ToolsMenuView
            return Destination(ToolsMenuView)

        elif button_data[selected_menu_num] == self.SETTINGS:
            from seedsigner.views.settings_views import SettingsMenuView
            return Destination(SettingsMenuView)
'''

MAIN_MENU_SEEDPASS = '''class MainMenuView(View):  # SeedPass
    """
    SeedPass home menu. Three ways to get a seed in memory -- everything then
    routes into the password flow via SeedOptionsView's redirect -- plus
    SeedSigner's Settings, left in place.
    """
    NEW_SEED = ButtonOption("New seed", FontAwesomeIconConstants.CAMERA)
    SCAN = ButtonOption("Scan", SeedSignerIconConstants.SCAN)
    SEEDS = ButtonOption("Seeds", SeedSignerIconConstants.SEEDS)
    SETTINGS = ButtonOption("Settings", SeedSignerIconConstants.SETTINGS)

    def run(self):
        from seedsigner.gui.screens.screen import MainMenuScreen
        button_data = [self.NEW_SEED, self.SCAN, self.SEEDS, self.SETTINGS]
        selected_menu_num = self.run_screen(
            MainMenuScreen,
            title=_("Passwords"),
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__POWER_BUTTON:
            return Destination(PowerOptionsView)

        if button_data[selected_menu_num] == self.NEW_SEED:
            from seedsigner.views.tools_views import ToolsImageEntropyLivePreviewView
            return Destination(ToolsImageEntropyLivePreviewView)

        elif button_data[selected_menu_num] == self.SCAN:
            from seedsigner.views.scan_views import ScanView
            return Destination(ScanView)

        elif button_data[selected_menu_num] == self.SEEDS:
            from seedsigner.views.seed_views import SeedsMenuView
            return Destination(SeedsMenuView)

        elif button_data[selected_menu_num] == self.SETTINGS:
            from seedsigner.views.settings_views import SettingsMenuView
            return Destination(SettingsMenuView)
'''


class Patch:
    """A single anchored replacement in an existing SeedSigner file."""

    def __init__(self, relative_path: str, anchor: str, addition: str, marker: str):
        self.relative_path = relative_path
        self.anchor = anchor        # exact text that must be present
        self.addition = addition    # replaces `anchor` when applied
        self.marker = marker        # unique string proving the patch is applied

    def is_applied(self, text: str) -> bool:
        return self.marker in text

    def apply(self, text: str) -> str:
        if self.anchor not in text:
            raise RuntimeError(
                f"Could not find the expected anchor in {self.relative_path}.\n"
                f"\n"
                f"SeedPass targets SeedSigner commit {TESTED_COMMIT[:12]} and will not\n"
                f"apply to older releases. Between tag 0.8.7 and that commit, SeedSigner\n"
                f"refactored its seed views from `seed_num: int` to `seed: Seed`; SeedPass\n"
                f"uses the newer API throughout, so this is not a one-line fix.\n"
                f"\n"
                f"Check what you have:\n"
                f"    git -C <seedsigner> rev-parse HEAD\n"
                f"\n"
                f"and check it out if needed:\n"
                f"    git -C <seedsigner> checkout {TESTED_COMMIT}"
            )
        if text.count(self.anchor) > 1:
            raise RuntimeError(f"Anchor is ambiguous in {self.relative_path}; patch by hand.")
        return text.replace(self.anchor, self.addition)

    def revert(self, text: str) -> str:
        return text.replace(self.addition, self.anchor)


PATCHES = [
    # Remove the sponsor logo from the splash screen.
    #
    # SeedSigner's opening splash reads "With support from:" above the Human
    # Rights Foundation logo. HRF sponsors SeedSigner; they have nothing to do
    # with SeedPass, and displaying their logo on a device running modified
    # firmware would claim an endorsement that does not exist. That is a false
    # statement about a real organisation, not a cosmetic detail.
    #
    # The empty partner list is what turns it off: get_random_partner is only
    # reached when the list is non-empty, so the whole block is skipped.
    Patch(
        relative_path="src/seedsigner/views/screensaver.py",
        marker="SeedPass: no sponsor",
        anchor=(
            "        self.partners = [\n"
            "            \"hrf\",\n"
            "        ]\n"
        ),
        addition=(
            "        # SeedPass: no sponsor. HRF supports SeedSigner, not this\n"
            "        # fork, and showing their logo here would claim an\n"
            "        # endorsement that was never given.\n"
            "        self.partners = []\n"
        ),
    ),
    Patch(
        relative_path="src/seedsigner/views/screensaver.py",
        marker="if not self.partners:",
        anchor=(
            "            # Set up the partner logo\n"
            "            partner_logo: Image.Image = self.partner_logos[self.get_random_partner()]\n"
        ),
        addition=(
            "            # SeedPass: skipped entirely when there is no sponsor.\n"
            "            if not self.partners:\n"
            "                self.renderer.show_image()\n"
            "                return\n"
            "\n"
            "            # Set up the partner logo\n"
            "            partner_logo: Image.Image = self.partner_logos[self.get_random_partner()]\n"
        ),
    ),

    # SeedPass QR types the stock decoder does not recognise. Handled where the
    # scanner gives up, so nothing SeedSigner already understands is affected:
    # if a QR reaches this branch, stock SeedSigner would have shown
    # "not yet implemented".
    Patch(
        relative_path="src/seedsigner/views/scan_views.py",
        marker="seedpass_scan_views",
        anchor=(
            "            else:\n"
            "                return Destination(NotYetImplementedView)\n"
        ),
        addition=(
            "            else:\n"
            "                from seedsigner.views.seedpass_scan_views import (  # SeedPass\n"
            "                    route_seedpass_qr,\n"
            "                )\n"
            "                seedpass_destination = route_seedpass_qr(self.decoder)\n"
            "                if seedpass_destination is not None:\n"
            "                    return seedpass_destination\n"
            "\n"
            "                return Destination(NotYetImplementedView)\n"
        ),
    ),

    # 1a. `FontAwesomeIconConstants` is needed for the camera icon on the new
    #     Home menu; view.py only imports SeedSignerIconConstants today.
    Patch(
        relative_path="src/seedsigner/views/view.py",
        marker="from seedsigner.gui.components import FontAwesomeIconConstants",
        anchor="from seedsigner.gui.components import SeedSignerIconConstants\n",
        addition=(
            "from seedsigner.gui.components import SeedSignerIconConstants\n"
            "from seedsigner.gui.components import FontAwesomeIconConstants  # SeedPass\n"
        ),
    ),

    # 1b. Replace the Home menu itself.
    Patch(
        relative_path="src/seedsigner/views/view.py",
        marker="class MainMenuView(View):  # SeedPass",
        anchor=MAIN_MENU_ORIGINAL,
        addition=MAIN_MENU_SEEDPASS,
    ),

    # 2. Every "load a seed" path in SeedSigner finalizes at SeedOptionsView.
    #    Redirect it so photo entropy, QR scan, manual entry and the seed list
    #    all land in the password flow. Done as a redirect in __post_init__ so
    #    the options screen never renders.
    Patch(
        relative_path="src/seedsigner/views/seed_views.py",
        marker="SeedPassMenuView",
        anchor=(
            "    def __init__(self, seed: Seed):\n"
            "        super().__init__()\n"
            "        self.seed = seed\n"
            "\n"
            "\n"
            "    def run(self):\n"
            "        from seedsigner.controller import Controller\n"
            "        from seedsigner.views.psbt_views import PSBTOverviewView\n"
        ),
        addition=(
            "    def __init__(self, seed: Seed):\n"
            "        super().__init__()\n"
            "        self.seed = seed\n"
            "\n"
            "        # SeedPass: this is a password-only device, so the generic seed\n"
            "        # options menu is bypassed entirely.\n"
            "        #\n"
            "        # Message signing is the exception. It is reached by scanning a\n"
            "        # request QR, and it routes through here to pick a seed; an\n"
            "        # unconditional redirect would swallow it. Let that one flow past.\n"
            "        from seedsigner.controller import Controller as _Controller\n"
            "        if self.controller.resume_main_flow != _Controller.FLOW__SIGN_MESSAGE:\n"
            "            from seedsigner.views.seedpass_views import SeedPassMenuView\n"
            "            self.set_redirect(Destination(SeedPassMenuView, view_args=dict(seed=self.seed)))\n"
            "\n"
            "\n"
            "    def run(self):\n"
            "        from seedsigner.controller import Controller\n"
            "        from seedsigner.views.psbt_views import PSBTOverviewView\n"
        ),
    ),
]


def resolve_target(raw: str) -> Path:
    target = Path(raw).expanduser().resolve()
    if not (target / "src" / "seedsigner" / "controller.py").is_file():
        sys.exit(f"error: {target} does not look like a SeedSigner source tree "
                 f"(no src/seedsigner/controller.py)")
    return target


def replace_files(source: Path, target: Path) -> None:
    """
    Swap in SeedPass's versions of existing upstream files, keeping the
    originals so the change is reversible.
    """
    for relative in REPLACED_FILES:
        src = source / relative
        dst = target / relative
        if not src.is_file():
            continue

        backup = dst.with_name(dst.name + BACKUP_SUFFIX)
        if dst.is_file() and not backup.exists():
            shutil.copy2(dst, backup)

        shutil.copy2(src, dst)
        print(f"  replaced {relative}")


def restore_files(target: Path) -> None:
    for relative in REPLACED_FILES:
        dst = target / relative
        backup = dst.with_name(dst.name + BACKUP_SUFFIX)
        if backup.is_file():
            shutil.move(str(backup), str(dst))
            print(f"  restored {relative}")


def copy_new_files(source: Path, target: Path, install_tests: bool) -> None:
    for relative in NEW_FILES:
        src = source / relative
        dst = target / relative
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        print(f"  wrote {relative}")

    if install_tests:
        for src_rel, dst_rel in TEST_FILES:
            src = source / src_rel
            if not src.is_file():
                continue
            dst = target / dst_rel
            if not dst.parent.is_dir():
                continue
            shutil.copy2(src, dst)
            print(f"  wrote {dst_rel}")


def remove_new_files(target: Path) -> None:
    for relative in NEW_FILES + [dst for _, dst in TEST_FILES]:
        path = target / relative
        if path.is_file():
            path.unlink()
            print(f"  removed {relative}")


def check_patches(target: Path) -> None:
    """
    Validate every anchor before changing anything.

    Without this, a mismatch partway through leaves the tree half-patched: some
    files edited, some not, and no clean way back. Check first, then apply.
    """
    problems = []
    for patch in PATCHES:
        text = (target / patch.relative_path).read_text()
        if patch.is_applied(text):
            continue
        count = text.count(patch.anchor)
        if count == 0:
            problems.append(f"{patch.relative_path}: anchor not found")
        elif count > 1:
            problems.append(f"{patch.relative_path}: anchor is ambiguous")

    if problems:
        raise RuntimeError(
            "This SeedSigner checkout is not one SeedPass can patch:\n  "
            + "\n  ".join(problems)
            + f"\n\n"
            f"SeedPass targets SeedSigner commit {TESTED_COMMIT[:12]} and will not\n"
            f"apply to older releases. Between tag 0.8.7 and that commit, SeedSigner\n"
            f"refactored its seed views from `seed_num: int` to `seed: Seed`; SeedPass\n"
            f"uses the newer API throughout, so this is not a one-line fix.\n\n"
            f"Check what you have:\n"
            f"    git -C <seedsigner> rev-parse HEAD\n\n"
            f"and check it out if needed:\n"
            f"    git -C <seedsigner> checkout {TESTED_COMMIT}\n\n"
            f"Nothing has been modified."
        )


def apply_patches(target: Path, revert: bool) -> None:
    for patch in PATCHES:
        path = target / patch.relative_path
        text = path.read_text()

        if revert:
            if not patch.is_applied(text):
                print(f"  {patch.relative_path}: nothing to revert")
                continue
            path.write_text(patch.revert(text))
            print(f"  reverted {patch.relative_path}")
            continue

        if patch.is_applied(text):
            print(f"  {patch.relative_path}: already patched")
            continue

        path.write_text(patch.apply(text))
        print(f"  patched {patch.relative_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Install SeedPass into a SeedSigner source tree")
    parser.add_argument("seedsigner_path", help="Path to the SeedSigner repo or /opt/seedsigner")
    parser.add_argument("--revert", action="store_true", help="Remove SeedPass again")
    parser.add_argument("--no-tests", action="store_true", help="Skip copying the test files")
    args = parser.parse_args()

    source = Path(__file__).parent.resolve()
    target = resolve_target(args.seedsigner_path)

    if args.revert:
        print(f"Reverting SeedPass in {target}")
        apply_patches(target, revert=True)
        restore_files(target)
        remove_new_files(target)
        print("\nDone. Restart SeedSigner.")
        return

    print(f"Installing SeedPass into {target}")
    check_patches(target)
    copy_new_files(source, target, install_tests=not args.no_tests)
    replace_files(source, target)
    apply_patches(target, revert=False)
    print("\nDone. Restart SeedSigner.")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        # A clean message beats a traceback: the usual cause is a version
        # mismatch, which is a user-facing problem, not a crash.
        sys.exit(f"\nerror: {e}")
