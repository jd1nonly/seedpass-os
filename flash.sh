#!/usr/bin/env bash
#
# flash.sh — write a SeedPass image to an SD card, then verify the write.
#
#   ./flash.sh                                   # list candidate devices
#   ./flash.sh images/seedpass_os....img /dev/sdX
#
# Writing to the wrong device destroys it. This script refuses obvious mistakes
# and makes you type the device name to confirm, but it cannot know which disk
# is yours. Check twice.
#
set -o errexit -o pipefail -o nounset

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

# ------------------------------------------------------------------ list mode

list_devices() {
    say "Removable block devices"

    case "$(uname -s)" in
        Linux)
            if command -v lsblk >/dev/null; then
                lsblk -d -o NAME,SIZE,RM,RO,TYPE,MODEL | awk 'NR==1 || $3==1'
                echo
                echo "RM=1 means removable. Your SD card should appear there,"
                echo "with a size that matches the card."
            else
                die "lsblk not found; identify the device yourself"
            fi
            ;;
        Darwin)
            diskutil list external physical
            ;;
        *)
            die "Unsupported OS. Use Balena Etcher instead: https://etcher.balena.io/"
            ;;
    esac

    cat <<'EOF'

Then:

    ./flash.sh <image> <device>

On Linux the device is the whole disk (/dev/sdb), not a partition (/dev/sdb1).
On macOS use the raw node (/dev/rdisk4) -- it is far faster than /dev/disk4.
EOF
}

if [ $# -eq 0 ]; then
    list_devices
    exit 0
fi

[ $# -eq 2 ] || die "usage: ./flash.sh <image> <device>   (no args to list devices)"

IMAGE="$1"
DEVICE="$2"

# ------------------------------------------------------------------ safety

[ -f "$IMAGE" ] || die "no such image: $IMAGE"
[ -b "$DEVICE" ] || die "$DEVICE is not a block device"

# Refuse anything that looks like a partition rather than a whole disk. Writing
# an image to a partition produces a card that cannot boot.
case "$DEVICE" in
    *[0-9]) case "$DEVICE" in
                /dev/sd[a-z][0-9]*|/dev/nvme*p[0-9]*|/dev/mmcblk*p[0-9]*)
                    die "$DEVICE looks like a partition. Use the whole disk."
                    ;;
            esac
            ;;
esac

# Refuse a disk that currently hosts a mounted filesystem the system is using.
if command -v lsblk >/dev/null; then
    MOUNTS="$(lsblk -no MOUNTPOINT "$DEVICE" 2>/dev/null | grep -v '^$' || true)"

    for mp in $MOUNTS; do
        case "$mp" in
            /|/boot|/home|/usr|/var)
                die "$DEVICE has $mp mounted. That is your system disk, not an SD card."
                ;;
        esac
    done

    # `|| true` matters: under errexit+pipefail a failed lsblk would abort the
    # script here, before the confirmation prompt, with no message at all.
    REMOVABLE="$(lsblk -dno RM "$DEVICE" 2>/dev/null | tr -d ' ' || true)"
    if [ -z "$REMOVABLE" ]; then
        echo "Warning: could not determine whether $DEVICE is removable." >&2
    elif [ "$REMOVABLE" != "1" ]; then
        echo "Warning: $DEVICE is not marked removable." >&2
        echo "Some USB card readers report this way, but so does an internal disk." >&2
    fi
fi

# ------------------------------------------------------------------ confirm

IMAGE_SIZE=$(stat -c%s "$IMAGE" 2>/dev/null || stat -f%z "$IMAGE")
DEVICE_DESC="$(lsblk -dno SIZE,MODEL "$DEVICE" 2>/dev/null || echo unknown)"

if [ -f "$IMAGE.sha256" ]; then
    say "Checking the image against its recorded hash"
    (cd "$(dirname "$IMAGE")" && sha256sum -c "$(basename "$IMAGE").sha256")
fi

say "About to overwrite $DEVICE"
cat <<EOF

  image:   $IMAGE  ($(( IMAGE_SIZE / 1024 / 1024 )) MiB)
  device:  $DEVICE  ($DEVICE_DESC)

Everything currently on $DEVICE will be destroyed.
EOF

printf '\nType the device name to confirm (%s): ' "$DEVICE"
read -r CONFIRM
[ "$CONFIRM" = "$DEVICE" ] || die "cancelled"

# Unmount anything auto-mounted from the card, or dd will fight the kernel.
if command -v lsblk >/dev/null; then
    for part in $(lsblk -lno NAME "$DEVICE" 2>/dev/null | tail -n +2 || true); do
        umount "/dev/$part" 2>/dev/null || true
    done
fi

# ------------------------------------------------------------------ write

say "Writing"
dd if="$IMAGE" of="$DEVICE" bs=4M conv=fsync status=progress
sync

# ------------------------------------------------------------------ verify

say "Verifying"
echo "Reading the card back and comparing. This takes about as long as the write."

IMAGE_HASH="$(sha256sum "$IMAGE" | cut -d' ' -f1)"
CARD_HASH="$(dd if="$DEVICE" bs=4M count=$(( (IMAGE_SIZE + 4194303) / 4194304 )) \
                iflag=fullblock 2>/dev/null | head -c "$IMAGE_SIZE" | sha256sum | cut -d' ' -f1)"

if [ "$IMAGE_HASH" = "$CARD_HASH" ]; then
    say "Verified"
    echo "The card matches the image byte for byte."
    echo "$IMAGE_HASH"
else
    say "MISMATCH"
    echo "  image: $IMAGE_HASH" >&2
    echo "  card:  $CARD_HASH" >&2
    echo >&2
    echo "Do not use this card. Re-flash, and if it fails again try another card" >&2
    echo "or reader -- silent write failures are a common symptom of both." >&2
    exit 1
fi
