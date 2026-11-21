#!/bin/sh
# Fetch the kernel build inputs into the docker volume "gbos-ksrc":
#
#   /build/src                     AOSP kernel/common (android17-6.18) at the pinned commit
#   /build/inputs/clang-r584948c  AOSP clang prebuilt (the toolchain build_kernel.sh and the patch scripts use)
#   /build/inputs/KernelSU        KernelSU sources (tiann/KernelSU, tag v3.3.1)
#
# Everything is skipped when it is already there, so re-running is cheap.
# Needs: docker (running), git, curl, tar. ~2.5 GB of downloads, ~7 GB in the volume.
set -e
cd "$(dirname "$0")/.."
ROOT=$(pwd)

VOL=gbos-ksrc
KSRC_COMMIT=3938c8d97142d5cf31543aa96f864a2cf832dda0   # AOSP kernel/common android17-6.18
KSRC_TAR=kernel-common-$KSRC_COMMIT.tar.gz
# +archive/<commit>.tar.gz is generated on the fly by gitiles: its bytes change between
# downloads even for the same commit (gzip/tar metadata). If this pin mismatches, verify the
# tarball with `tar -tzf`, check `tar -xzOf <file> Makefile | head` reports 6.18.21, then
# update this value to the sha256 printed in the error. Do not accept a corrupt archive.
KSRC_SHA=3eb425501acd744021fc0f10552a7b286518190538c4518362279d550a5c6ee7
CLANG_TAG=android-17.0.0_r1        # AOSP prebuilts/clang/host/linux-x86
CLANG_DIR=clang-r584948c           # must match C= in kernel/build_kernel.sh and kernel/isa_emu_patch/*.sh
KSU_TAG=v3.3.1

DL=$ROOT/build/dl
mkdir -p "$DL"
say() { printf '\n== %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

command -v docker >/dev/null || die "docker is not installed"
docker info >/dev/null 2>&1 || die "docker is installed but not running"
docker volume create "$VOL" >/dev/null

# --- 1. kernel source --------------------------------------------------------------
if docker run --rm -v "$VOL":/build debian:trixie test -f /build/src/Makefile; then
  say "kernel source: present in $VOL"
else
  say "kernel source: android.googlesource.com kernel/common @ $KSRC_COMMIT"
  [ -f "$DL/$KSRC_TAR" ] || curl -fL --retry 5 -o "$DL/$KSRC_TAR" \
    "https://android.googlesource.com/kernel/common/+archive/$KSRC_COMMIT.tar.gz"
  got=$(sha "$DL/$KSRC_TAR")
  [ "$got" = "$KSRC_SHA" ] || die "sha256 mismatch for $KSRC_TAR ($got); delete it and retry"
  docker run --rm -v "$VOL":/build -v "$DL":/dl:ro debian:trixie \
    bash -c "set -e; mkdir -p /build/src; tar -xzf /dl/$KSRC_TAR -C /build/src"
fi

# --- 2. AOSP clang -----------------------------------------------------------------
if docker run --rm -v "$VOL":/build debian:trixie test -x /build/inputs/$CLANG_DIR/bin/clang; then
  say "clang: present in $VOL"
else
  say "clang: android.googlesource.com prebuilts/clang/host/linux-x86 ($CLANG_TAG)"
  rm -rf "$DL/clang-prebuilts"
  git clone --filter=blob:none --sparse --depth 1 --branch "$CLANG_TAG" \
    https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86 "$DL/clang-prebuilts"
  git -C "$DL/clang-prebuilts" sparse-checkout set "$CLANG_DIR"
  # Only the toolchain is needed; the NDK runtimes and the C++ library are not.
  rm -rf "$DL/clang-prebuilts/$CLANG_DIR"/{android_libc++,musl,python3,runtimes_ndk_cxx}
  docker run --rm -v "$VOL":/build -v "$DL":/dl:ro debian:trixie \
    bash -c "set -e; mkdir -p /build/inputs; cp -a /dl/clang-prebuilts/$CLANG_DIR /build/inputs/"
fi

# --- 3. KernelSU -------------------------------------------------------------------
if docker run --rm -v "$VOL":/build debian:trixie test -d /build/inputs/KernelSU/kernel; then
  say "KernelSU: present in $VOL"
else
  say "KernelSU: github.com/tiann/KernelSU ($KSU_TAG)"
  rm -rf "$DL/KernelSU"
  git clone https://github.com/tiann/KernelSU "$DL/KernelSU"
  git -C "$DL/KernelSU" checkout "$KSU_TAG"
  # The kernel side derives its version from the commit count; a shallow clone would
  # report a wrong version, so keep the full history.
  docker run --rm -v "$VOL":/build -v "$DL":/dl:ro debian:trixie \
    bash -c "set -e; rm -rf /build/inputs/KernelSU; cp -a /dl/KernelSU /build/inputs/KernelSU; chown -R root:root /build/inputs/KernelSU"
fi

say "done: $VOL now holds /build/src, /build/inputs/$CLANG_DIR and /build/inputs/KernelSU"
echo "Next: kernel/kernelsu/apply.sh (in the build container), then kernel/isa_emu_patch/build.sh"
