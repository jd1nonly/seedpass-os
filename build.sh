#!/usr/bin/env bash
#
# build.sh — build a bootable SeedPass SD card image, start to finish.
#
#   ./build.sh              # Pi Zero 1.3 (the recommended air-gapped board)
#   ./build.sh --pi02w      # other boards: --pi0 --pi02w --pi2 --pi4
#   ./build.sh --no-docker  # build directly on this machine, no container
#
# Everything needed is in this directory. The script fetches SeedSigner OS at a
# pinned commit, applies SeedPass to it, and runs the Buildroot image build in
# Docker. The result is written to ./images/.
#
# The first build takes 2-4 hours: Buildroot compiles a cross toolchain from
# source. Later builds reuse ccache and are much faster.
#
set -o errexit -o pipefail -o nounset

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pinned so two people building from this package get the same inputs. Bump both
# together, and re-check that enable_seedpass_os.py still applies afterwards.
SEEDSIGNER_OS_REPO="https://github.com/SeedSigner/seedsigner-os.git"
SEEDSIGNER_OS_COMMIT="04e8ca87f5bd980bd65bda75aa694af960ababef"

# The exact SeedSigner app commit SeedPass was written and tested against.
#
# A commit, not the 0.8.7 tag: between 0.8.7 (June 2026) and this commit,
# SeedSigner refactored its seed views from `seed_num: int` to `seed: Seed`.
# SeedPass targets the newer API, so it does not apply to 0.8.7 and earlier.
# Pinning the SHA also makes the build reproducible in a way that tracking a
# moving branch would not.
APP_COMMIT="${APP_COMMIT:-5088588dd4f913a489329d2422b0f925ed281856}"

BOARD="--pi0"
USE_DOCKER=1
for arg in "$@"; do
    case "$arg" in
        --pi0|--pi02w|--pi2|--pi4) BOARD="$arg" ;;
        --no-docker) USE_DOCKER=0 ;;
        -h|--help)
            sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "Unknown option: $arg" >&2; exit 1 ;;
    esac
done

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# ------------------------------------------------------------------ preflight

# Unzipping on Windows, or copying from /mnt/c, drags these along. They are
# harmless but would be copied into the image, so clear them first.
find "$HERE" -name '*:Zone.Identifier' -delete 2>/dev/null || true

say "Checking prerequisites"

for tool in git python3; do
    command -v "$tool" >/dev/null || { echo "Missing: $tool"; exit 1; }
done

# Dependencies Buildroot needs when building on this machine directly. Taken
# from seedsigner-os's Dockerfile, which is the combination known to work.
HOST_DEPS="locales lsb-release git wget make binutils gcc g++ patch gzip bzip2 \
perl tar cpio unzip rsync file bc libssl-dev build-essential libncurses-dev \
mtools fdisk dosfstools ccache python3 python3-pip python3-virtualenv"

if [ "$USE_DOCKER" -eq 1 ]; then
    if ! command -v docker >/dev/null; then
        cat >&2 <<'EOF'
Missing: docker

The image is built inside a container so that the result does not depend on
what happens to be installed on your machine. Install Docker Desktop, or
Docker Engine on Linux:

    https://docs.docker.com/engine/install/

Or build directly on this machine instead, with no container:

    ./build.sh --no-docker
EOF
        exit 1
    fi

    if docker compose version >/dev/null 2>&1; then
        COMPOSE="docker compose"
    elif command -v docker-compose >/dev/null; then
        COMPOSE="docker-compose"
    else
        echo "Missing: docker compose plugin" >&2
        exit 1
    fi
    echo "  docker present"
else
    # No container: Buildroot runs against whatever is installed here. Fine on a
    # Debian-based system, which includes WSL Ubuntu.
    MISSING=""
    for pkg in make gcc g++ patch cpio rsync bc unzip wget file mtools; do
        command -v "$pkg" >/dev/null 2>&1 || MISSING="$MISSING $pkg"
    done
    command -v virtualenv >/dev/null 2>&1 || python3 -m virtualenv --version >/dev/null 2>&1 \
        || MISSING="$MISSING virtualenv"

    if [ -n "$MISSING" ]; then
        echo "Missing build tools:$MISSING" >&2
        echo >&2
        echo "On Debian/Ubuntu (including WSL):" >&2
        echo >&2
        echo "    sudo apt update && sudo apt install -y $HOST_DEPS" >&2
        exit 1
    fi
    echo "  building without a container; host tools present"
fi

FREE_KB=$(df -Pk "$HERE" | awk 'NR==2 {print $4}')
if [ "$FREE_KB" -lt 20971520 ]; then
    echo "Warning: less than 20 GB free here. Buildroot needs room for a toolchain." >&2
fi


# ---------------------------------------------------------- fetch seedsigner-os

OS_DIR="$HERE/seedsigner-os"

if [ ! -d "$OS_DIR/.git" ]; then
    say "Fetching SeedSigner OS at ${SEEDSIGNER_OS_COMMIT:0:12}"
    # --recurse-submodules is not optional: buildroot itself is a submodule at
    # opt/buildroot, and the build runs make inside it.
    git clone --recurse-submodules "$SEEDSIGNER_OS_REPO" "$OS_DIR"
else
    say "Reusing existing seedsigner-os checkout"
fi

cd "$OS_DIR"

# Undo any previous SeedPass edits before checking out, so the working tree is
# clean and the commit pin actually means something.
if grep -q "seedpass_patch_dir" opt/build.sh 2>/dev/null; then
    python3 "$HERE/enable_seedpass_os.py" "$OS_DIR" --revert >/dev/null
fi

git fetch --quiet origin
git checkout --quiet "$SEEDSIGNER_OS_COMMIT"

# Re-sync submodules after checkout: the pinned commit may point at a different
# buildroot revision than whatever is currently checked out.
git submodule update --init --recursive --quiet

ACTUAL="$(git rev-parse HEAD)"
if [ "$ACTUAL" != "$SEEDSIGNER_OS_COMMIT" ]; then
    echo "Commit pin mismatch: expected $SEEDSIGNER_OS_COMMIT, got $ACTUAL" >&2
    exit 1
fi
echo "  pinned at $ACTUAL"

if [ ! -f "$OS_DIR/opt/buildroot/Makefile" ]; then
    echo "buildroot submodule is missing or empty at opt/buildroot" >&2
    echo "Try: git -C \"$OS_DIR\" submodule update --init --recursive" >&2
    exit 1
fi
echo "  buildroot submodule present"

cd "$HERE"

# ------------------------------------------------------------------ apply SeedPass

say "Applying SeedPass"
python3 "$HERE/enable_seedpass_os.py" "$OS_DIR" "$HERE/seedpass" --quiet

bash -n "$OS_DIR/opt/build.sh"
echo "  patched build.sh is valid shell"

# ---------------------------------------------------------------------- build

say "Building the image ($BOARD, app ${APP_COMMIT:0:12})"

# Buildroot compiles a cross toolchain from scratch the first time and reuses
# ccache afterwards, so the honest estimate depends on whether a cache survived.
if [ -d "$OS_DIR/.ccache" ] || [ -d "$OS_DIR/opt/.ccache" ]; then
    echo "A ccache was found, so this should be well short of a first build."
else
    echo "This is the long part. Expect 2-4 hours on a first run."
fi
echo

if [ "$USE_DOCKER" -eq 1 ]; then
    # opt/ is bind-mounted to /opt by docker-compose.yml, so the patch directory
    # is addressed by its path *inside* the container.
    cd "$OS_DIR"
    SS_ARGS="$BOARD --app-commit-id=$APP_COMMIT --app-patch=/opt/seedpass" \
        $COMPOSE up --force-recreate --build
else
    # No container, so the same directory is addressed by its real path.
    cd "$OS_DIR/opt"
    ./build.sh "$BOARD" "--app-commit-id=$APP_COMMIT" "--app-patch=$OS_DIR/opt/seedpass"
fi

# --------------------------------------------------------------------- collect

mkdir -p "$HERE/images"
shopt -s nullglob
BUILT=("$OS_DIR"/images/seedpass_os.*.img)
shopt -u nullglob

if [ ${#BUILT[@]} -eq 0 ]; then
    echo "No image produced. Scroll up for the Buildroot error." >&2
    exit 1
fi

for img in "${BUILT[@]}"; do
    cp -f "$img" "$HERE/images/"
    name="$(basename "$img")"
    (cd "$HERE/images" && sha256sum "$name" > "$name.sha256")
    say "Built: images/$name"
    cat "$HERE/images/$name.sha256"
done

cat <<EOF

Next: write it to a card.

    ./flash.sh images/$(basename "${BUILT[-1]}") /dev/sdX

Run ./flash.sh with no arguments first to list candidate devices.
EOF
