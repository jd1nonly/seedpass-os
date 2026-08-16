#!/usr/bin/env python3
"""
Turn a SeedSigner OS checkout into a SeedPass OS builder.

SeedSigner OS builds its image by cloning the SeedSigner app repo into
`opt/rootfs-overlay/opt`, compiling translations, then handing the whole tree to
Buildroot. There is no supported way to modify the app in between -- the closest
existing options are `--app-repo` (needs a published fork) and `--skip-repo`
(skips translation compilation, which the app needs at runtime).

So this adds one option, `--app-patch=<dir>`, which runs a patch script against
the freshly cloned app *before* translations are compiled. That is the only
place a modification can land and still get the same treatment as stock code.

It also copies the SeedPass payload into `opt/` so it is visible inside the
build container, and renames the output image so a SeedPass card is never
mistaken for a stock SeedSigner one.

Usage:

    python3 enable_seedpass_os.py /path/to/seedsigner-os /path/to/seedpass
    python3 enable_seedpass_os.py /path/to/seedsigner-os --revert

Then build as SeedSigner OS documents, with one extra flag:

    cd /path/to/seedsigner-os
    SS_ARGS="--pi0 --app-branch=0.8.7 --app-patch=/opt/seedpass" \\
        docker compose up --force-recreate --build

Re-running is safe: applied edits are detected and skipped.
"""
import argparse
import shutil
import sys

from pathlib import Path


# Where the SeedPass payload is placed inside the seedsigner-os checkout.
# opt/ is bind-mounted to /opt in the build container, so this path is what the
# --app-patch flag refers to *inside* the container.
PAYLOAD_SUBDIR = "opt/seedpass"
PAYLOAD_IN_CONTAINER = "/opt/seedpass"

# Files copied into the image's root filesystem. Currently the USB gadget init
# script, which is only needed for FIDO2 and skips itself harmlessly when there
# is no USB device controller.
OVERLAY_SOURCE = "overlay"
OVERLAY_TARGET = "opt/rootfs-overlay"


class Patch:
    """A single anchored replacement in build.sh."""

    def __init__(self, name: str, anchor: str, replacement: str, marker: str):
        self.name = name
        self.anchor = anchor
        self.replacement = replacement
        self.marker = marker

    def is_applied(self, text: str) -> bool:
        return self.marker in text

    def apply(self, text: str) -> str:
        if self.anchor not in text:
            raise RuntimeError(
                f"Could not find the anchor for '{self.name}' in opt/build.sh.\n"
                f"Your seedsigner-os checkout differs from the one this was written\n"
                f"against. The edits are small; see PATCHES in this file and apply\n"
                f"them by hand."
            )
        if text.count(self.anchor) > 1:
            raise RuntimeError(f"Anchor for '{self.name}' is ambiguous; patch by hand.")
        return text.replace(self.anchor, self.replacement)

    def revert(self, text: str) -> str:
        return text.replace(self.replacement, self.anchor)


PATCHES = [
    # 1. Declare the variable alongside the other repo globals.
    Patch(
        name="global variable",
        marker='seedpass_patch_dir=""',
        anchor='seedsigner_app_repo_branch="dev"\n',
        replacement=(
            'seedsigner_app_repo_branch="dev"\n'
            'seedpass_patch_dir=""   # SeedPass: set from the app patch flag\n'
        ),
    ),

    # 2. Document it in the help text.
    Patch(
        name="help text",
        marker="Directory holding a patch script",
        anchor='      --app-commit-id  Build image with specific repo commit id\n',
        replacement=(
            '      --app-commit-id  Build image with specific repo commit id\n'
            '      --app-patch      Directory holding a patch script to apply to the\n'
            '                       cloned app before translations are compiled\n'
        ),
    ),

    # 3. The function that applies it.
    Patch(
        name="apply_app_patch function",
        marker="apply_app_patch()",
        anchor="download_app_repo() {\n",
        replacement=(
            "apply_app_patch() {\n"
            "  # SeedPass: run a patch script against the freshly cloned app.\n"
            "  #\n"
            "  # Must happen after the clone and before compile_translations_and_fonts,\n"
            "  # so that any strings the patch introduces are compiled like the rest.\n"
            "  if [ -z \"${seedpass_patch_dir}\" ]; then\n"
            "    return\n"
            "  fi\n"
            "\n"
            "  if [ ! -f \"${seedpass_patch_dir}/install.py\" ]; then\n"
            "    echo \"ERROR: no install.py in ${seedpass_patch_dir}\" >&2\n"
            "    exit 1\n"
            "  fi\n"
            "\n"
            "  echo \"applying app patch from ${seedpass_patch_dir}\"\n"
            "  python3 \"${seedpass_patch_dir}/install.py\" \"${rootfs_overlay}/opt\" --no-tests || exit\n"
            "}\n"
            "\n"
            "download_app_repo() {\n"
        ),
    ),

    # 4. Call it at the one correct moment.
    Patch(
        name="apply_app_patch call",
        marker="  apply_app_patch\n  compile_translations_and_fonts",
        anchor="  compile_translations_and_fonts\n}\n",
        replacement="  apply_app_patch\n  compile_translations_and_fonts\n}\n",
    ),

    # 5. Accept the flag.
    Patch(
        name="argument parsing",
        marker="--app-patch=*)",
        anchor=(
            '  --app-commit-id=*)\n'
            '    APP_COMMITID=$(echo "${1}" | cut -d "=" -f2-); shift\n'
            '    ;;\n'
        ),
        replacement=(
            '  --app-commit-id=*)\n'
            '    APP_COMMITID=$(echo "${1}" | cut -d "=" -f2-); shift\n'
            '    ;;\n'
            '  --app-patch=*)\n'
            '    APP_PATCH=$(echo "${1}" | cut -d "=" -f2-); shift\n'
            '    ;;\n'
        ),
    ),

    # 6. Wire the parsed flag to the global.
    Patch(
        name="flag assignment",
        marker="seedpass_patch_dir=\"${APP_PATCH}\"",
        anchor=(
            '# check for custom app repo\n'
            'if ! [ -z ${APP_REPO} ]; then\n'
            '  seedsigner_app_repo="${APP_REPO}"\n'
            'fi\n'
        ),
        replacement=(
            '# check for custom app repo\n'
            'if ! [ -z ${APP_REPO} ]; then\n'
            '  seedsigner_app_repo="${APP_REPO}"\n'
            'fi\n'
            '\n'
            '# SeedPass: directory holding the app patch to apply after cloning\n'
            'if ! [ -z ${APP_PATCH} ]; then\n'
            '  seedpass_patch_dir="${APP_PATCH}"\n'
            'fi\n'
        ),
    ),

    # 7. Seed setuptools into the translation venv.
    #
    #    build.sh runs `python3 setup.py compile_catalog` inside a virtualenv.
    #    Since Python 3.12, virtualenv seeds only pip -- setuptools and wheel are
    #    no longer installed by default -- so that line dies with
    #    "ModuleNotFoundError: No module named 'setuptools'".
    #
    #    Bites the --no-docker path on any modern host. Harmless inside the
    #    Debian 12 container, whose older virtualenv still seeds it.
    Patch(
        name="setuptools in translation venv",
        marker="pip install setuptools",
        anchor=(
            '  # install depedencies for babel and fonttools(pyftsubset)\n'
            '  pip install babel || exit\n'
        ),
        replacement=(
            '  # install depedencies for babel and fonttools(pyftsubset)\n'
            '  # SeedPass: virtualenv stopped seeding setuptools at Python 3.12, and\n'
            '  # `setup.py compile_catalog` below needs it.\n'
            '  pip install setuptools || exit\n'
            '  pip install babel || exit\n'
        ),
    ),

    # 8. Name the output image for what it is. A SeedPass card behaves very
    #    differently from a stock SeedSigner one; the filename should say so.
    Patch(
        name="image naming",
        marker='image_basename=',
        anchor=(
            '  seedsigner_os_image_output="${image_dir}/seedsigner_os.'
            '${seedsigner_app_repo_branch}.${config_name}.img"\n'
        ),
        replacement=(
            '  # SeedPass: a patched image is not stock SeedSigner OS, so it does not\n'
            '  # get to carry that name.\n'
            '  image_basename="seedsigner_os"\n'
            '  if ! [ -z "${seedpass_patch_dir}" ]; then\n'
            '    image_basename="seedpass_os"\n'
            '  fi\n'
            '\n'
            '  seedsigner_os_image_output="${image_dir}/${image_basename}.'
            '${seedsigner_app_repo_branch}.${config_name}.img"\n'
        ),
    ),
    Patch(
        name="image naming (commit id variant)",
        marker='${image_basename}.${seedsigner_app_repo_commit_id}',
        anchor=(
            '    seedsigner_os_image_output="${image_dir}/seedsigner_os.'
            '${seedsigner_app_repo_commit_id}.${config_name}.img"\n'
        ),
        replacement=(
            '    seedsigner_os_image_output="${image_dir}/${image_basename}.'
            '${seedsigner_app_repo_commit_id}.${config_name}.img"\n'
        ),
    ),
]


def resolve_os_tree(raw: str) -> Path:
    target = Path(raw).expanduser().resolve()
    if not (target / "opt" / "build.sh").is_file():
        sys.exit(f"error: {target} does not look like a seedsigner-os checkout "
                 f"(no opt/build.sh)")
    return target


def copy_overlay(source: Path, os_tree: Path) -> None:
    """
    Merge our rootfs additions into seedsigner-os's overlay.

    Merged rather than replaced: the overlay already holds SeedSigner's own
    files, and clobbering it would produce an image that does not boot.
    """
    overlay = source / OVERLAY_SOURCE
    if not overlay.is_dir():
        return

    for item in overlay.rglob("*"):
        if item.is_dir() or item.name == "README.md":
            continue
        # Windows attaches these to anything downloaded from the internet, and
        # they survive an unzip. Copying them would put junk in the image.
        if ":Zone.Identifier" in item.name:
            continue

        relative = item.relative_to(overlay)
        destination = os_tree / OVERLAY_TARGET / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, destination)

        # Init scripts have to be executable, and zip archives do not always
        # preserve the bit.
        if "init.d" in relative.parts:
            destination.chmod(0o755)

        print(f"  wrote {OVERLAY_TARGET}/{relative}")


def remove_overlay(source: Path, os_tree: Path) -> None:
    overlay = source / OVERLAY_SOURCE
    if not overlay.is_dir():
        return

    for item in overlay.rglob("*"):
        if item.is_dir() or item.name == "README.md":
            continue
        if ":Zone.Identifier" in item.name:
            continue
        destination = os_tree / OVERLAY_TARGET / item.relative_to(overlay)
        if destination.is_file():
            destination.unlink()
            print(f"  removed {OVERLAY_TARGET}/{item.relative_to(overlay)}")


def copy_payload(os_tree: Path, payload: Path) -> None:
    if not (payload / "install.py").is_file():
        sys.exit(f"error: {payload} does not look like the SeedPass package "
                 f"(no install.py)")

    destination = os_tree / PAYLOAD_SUBDIR
    if destination.exists():
        shutil.rmtree(destination)

    shutil.copytree(
        payload, destination,
        ignore=shutil.ignore_patterns(
            "__pycache__", "*.pyc", ".git",
            # Windows "mark of the web" tags, which survive an unzip and would
            # otherwise be copied into the image.
            "*:Zone.Identifier",
        ),
    )
    print(f"  copied SeedPass payload -> {PAYLOAD_SUBDIR}/")


def apply_patches(os_tree: Path, revert: bool) -> None:
    path = os_tree / "opt" / "build.sh"
    text = path.read_text()

    for patch in PATCHES:
        if revert:
            if not patch.is_applied(text):
                print(f"  {patch.name}: nothing to revert")
                continue
            text = patch.revert(text)
            print(f"  reverted {patch.name}")
            continue

        if patch.is_applied(text):
            print(f"  {patch.name}: already applied")
            continue

        text = patch.apply(text)
        print(f"  patched {patch.name}")

    path.write_text(text)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Turn a seedsigner-os checkout into a SeedPass OS builder",
    )
    parser.add_argument("seedsigner_os_path", help="Path to a seedsigner-os checkout")
    parser.add_argument("seedpass_path", nargs="?",
                        help="Path to the seedpass package (required unless --revert)")
    parser.add_argument("--revert", action="store_true",
                        help="Undo the changes and remove the payload")
    parser.add_argument("--quiet", action="store_true",
                        help="Skip the closing build instructions (build.sh prints its own)")
    args = parser.parse_args()

    os_tree = resolve_os_tree(args.seedsigner_os_path)

    source = Path(__file__).parent.resolve()

    if args.revert:
        print(f"Reverting SeedPass OS support in {os_tree}")
        apply_patches(os_tree, revert=True)
        remove_overlay(source, os_tree)
        payload = os_tree / PAYLOAD_SUBDIR
        if payload.exists():
            shutil.rmtree(payload)
            print(f"  removed {PAYLOAD_SUBDIR}/")
        print("\nDone. This is a stock seedsigner-os checkout again.")
        return

    if not args.seedpass_path:
        parser.error("seedpass_path is required unless --revert is given")

    payload = Path(args.seedpass_path).expanduser().resolve()

    print(f"Enabling SeedPass OS in {os_tree}")
    copy_payload(os_tree, payload)
    copy_overlay(source, os_tree)
    apply_patches(os_tree, revert=False)

    if args.quiet:
        return

    print(f"""
Done. Build with:

    cd {os_tree}
    SS_ARGS="--pi0 --app-branch=0.8.7 --app-patch={PAYLOAD_IN_CONTAINER}" \\
        docker compose up --force-recreate --build

The image lands in images/ as seedpass_os.0.8.7.pi0.img.
Boards: --pi0, --pi02w, --pi2, --pi4.
""")


if __name__ == "__main__":
    main()
