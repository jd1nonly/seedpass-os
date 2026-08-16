# SeedPass OS

A bootable SD card image that turns a SeedSigner into an air-gapped password
generator.

**You need one file to flash: the `.img`.** How you get that file is up to you —
you can have GitHub build it, or build it yourself.

```bash
./flash.sh                                          # lists your removable drives
./flash.sh seedpass_os.0.8.7.pi0.img /dev/sdX       # write and verify
```

`flash.sh` needs nothing but the image. No Docker, no Python, no build.

---

## Getting the .img

**No prebuilt image ships with this package.** Producing one means compiling a
Linux system with Buildroot — a cross toolchain built from source, gigabytes of
downloads, 30 minutes to 4 hours. There is no way to hand you a `.img` without
that happening somewhere.

For a tool that guards your passwords, that is arguably the right default: an
image someone else built is one you are trusting blindly. The build is
reproducible precisely so you don't have to.

### Option A — let GitHub build it (nothing runs on your machine)

Push this folder to a GitHub repo, then **Actions → Build SeedPass OS image →
Run workflow**. Pick your board and wait 30–60 minutes. The `.img` and its
SHA-256 appear as a downloadable artifact on the run page.

Tagging a release (`git tag v1.0 && git push --tags`) does the same and attaches
the image to a GitHub Release, which gives you a stable URL and a published hash.

The workflow is `.github/workflows/build-image.yml`. It pins the same SeedSigner
OS commit and app version that `build.sh` does, so a CI image and a local one are
built from identical inputs.

### Option B — build it yourself

```bash
./build.sh              # Pi Zero 1.3, the recommended air-gapped board
./build.sh --pi02w      # or --pi0 --pi02w --pi2 --pi4
```

Needs Docker, ~20 GB free disk, and 2–4 hours the first time (later builds reuse
ccache and are much quicker). The image lands in `images/` with its SHA-256.

#### Without Docker

Buildroot doesn't need a container — the container only exists so the result
doesn't depend on what's installed on your machine. If you'd rather build
directly on a Debian-based system (WSL Ubuntu counts):

```bash
./build.sh --no-docker
```

It checks for the required tools first and prints the exact `apt install` line if
any are missing.

Two costs. Reproducibility: your host's compiler and library versions go into the
build, so two people may not get byte-identical images. And host Python matters —
this path is where the `setuptools` issue above shows up, which the patch now
handles, but newer Python versions may surface others the container would have
avoided.

#### On Windows

Docker Desktop is fine — it is the same daemon either way. WSL Ubuntu is a
lightweight VM, not a container, and with WSL Integration on, the `docker`
command inside Ubuntu is a thin client talking to Docker Desktop's engine. There
is no Docker-in-Docker and no second Linux running.

`build.sh` is a bash script, so run it from a **WSL Ubuntu** shell rather than
PowerShell:

1. Docker Desktop → Settings → Resources → **WSL Integration** → enable your
   distro. Check with `docker run --rm hello-world` inside Ubuntu.
2. Docker Desktop must be in **Linux containers** mode (the default). The build
   container is `debian:12`.
3. Put the project in the **WSL filesystem** (`~/seedpass-os`), never under
   `/mnt/c/...`. The Windows mount is far slower and mangles the permissions and
   symlinks Buildroot depends on.
4. `sudo apt install -y git python3` if missing, then `./build.sh`.

On Apple Silicon or any non-amd64 host, set
`export DOCKER_DEFAULT_PLATFORM=linux/amd64` first so the result matches an
amd64 build.

Building from PowerShell directly is possible — SeedSigner OS documents it — but
you must enable Windows **Developer Mode** and set
`git config --global core.autocrlf false`, `core.eol lf` and `core.symlinks true`
*before cloning*, or the buildroot submodule's symlinks break. Using WSL avoids
all of that.

Note that **WSL cannot reach a USB card reader**, so `flash.sh` will not work
there. Copy the finished `.img` to Windows and flash it with
[Balena Etcher](https://etcher.balena.io/).

---

## Flashing

```bash
./flash.sh
```

with no arguments lists removable devices. Then:

```bash
./flash.sh seedpass_os.0.8.7.pi0.img /dev/sdX
```

The script refuses partitions (`/dev/sdb1` — an image written to a partition
produces a card that cannot boot), refuses whole disks with `/`, `/boot` or
`/home` mounted, warns if the device isn't flagged removable, and makes you type
the device name to confirm. **It still cannot know which disk is yours.** Check
twice; writing to the wrong device destroys it.

If a `.sha256` sits next to the image it is checked first. After writing, the
card is read back and compared against the image. Silent write failures are a
common symptom of a failing card or reader, and you want to find that out now
rather than mid-recovery.

macOS: use the raw node (`/dev/rdisk4`, not `/dev/disk4`) — far faster.
Windows: use [Balena Etcher](https://etcher.balena.io/).

---

## What's in here

```
flash.sh                 write an .img to a card, then verify it
build.sh                 build the .img locally
enable_seedpass_os.py    the build-system patch (build.sh and CI call this)
seedpass/                the SeedPass application itself
.github/workflows/       CI that builds the .img for you
```

The device's behaviour is documented in [`seedpass/README.md`](seedpass/README.md)
and the derivation is specified in [`seedpass/SPEC.md`](seedpass/SPEC.md).

## How the integration works

SeedSigner OS clones the SeedSigner app into `opt/rootfs-overlay/opt`, compiles
translations, then hands the tree to Buildroot. Two existing options come close
but neither fits:

- `--app-repo` needs a *published fork* of the app repo — a fork to maintain and
  rebase every upstream release.
- `--skip-repo` lets you populate the overlay yourself, but skips
  `compile_translations_and_fonts`, which the app needs at runtime.

So `enable_seedpass_os.py` adds one option, **`--app-patch=<dir>`**, which runs
`seedpass/install.py` against the freshly cloned app *after* the clone and
*before* translations are compiled — the only point where a modification can land
and still get the same treatment as stock code. Seven smaller edits declare the
flag, wire it up, and rename the output image, because a SeedPass card behaves
very differently from a stock SeedSigner one. Total: 37 lines added, 2 changed,
in one file. `--revert` undoes it exactly.

Because it builds on SeedSigner OS rather than Raspberry Pi OS, the result has a
read-only root filesystem, no shell, no SSH, and no networking stack at all — not
disabled, absent.

---

## Status

**Verified.** The patcher applies to a real `seedsigner-os` checkout, all eight
edits land, `bash -n` accepts the result, `--help` shows the new flag, re-running
is a no-op, `--revert` gives a clean `git status`. I simulated what the build
container does — cloned the app into `rootfs-overlay/opt`, ran the
`apply_app_patch` function extracted from the patched `build.sh` — and confirmed
SeedPass lands in the tree, every patched file compiles, the derivation runs from
that tree, and its 58-test suite passes against it. `build.sh` was exercised
end-to-end with a stubbed Docker. `flash.sh`'s guards were exercised directly.
The CI workflow parses as valid YAML.

**Not verified: no image has ever been built, by me or by CI.** Buildroot needs
to download and compile a full cross toolchain, which was not possible in the
environment this was written in. The Buildroot half, the flashing and the boot
are all unexercised, and the workflow has never had a real run. Expect the first
build — wherever it happens — to take hours and possibly to surface problems this
could not reach.

Not audited.
