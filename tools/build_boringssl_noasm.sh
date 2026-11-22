#!/bin/sh
# Build a pure-C (no assembly) BoringSSL libcrypto for Android x86_64.
# No ADX/AVX/SHA-NI instructions are emitted, so it runs on any x86-64 CPU
# without relying on the kernel instruction emulator.
#
# Inputs (downloaded once):
#   build/dl/android-ndk-r30-linux.zip   (~704 MB, dl.google.com)
#   build/bssl/src                       (BoringSSL git checkout)
# Output:
#   build/bssl/out-android/libcrypto.so
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
B=$ROOT/build/bssl
NDK_ZIP=$ROOT/build/dl/android-ndk-r30-linux.zip
NDK=$B/android-ndk-r30

[ -f "$NDK_ZIP" ] || { echo "missing $NDK_ZIP" >&2; exit 1; }
if [ ! -x "$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/clang" ]; then
  echo "unpacking NDK..."
  mkdir -p "$B"
  unzip -q -o "$NDK_ZIP" -d "$B"
fi

C=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/clang
TC=$NDK/build/cmake/android.toolchain.cmake

echo "configuring BoringSSL (OPENSSL_NO_ASM=ON, Android x86_64)..."
cmake -S "$B/src" -B "$B/out-android" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$TC" \
  -DANDROID_ABI=x86_64 \
  -DANDROID_PLATFORM=android-35 \
  -DANDROID_STL=c++_shared \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON \
  -DOPENSSL_NO_ASM=ON

echo "building..."
cmake --build "$B/out-android" --target crypto ssl -j "$(nproc)"

ls -lh "$B/out-android/libcrypto.so" "$B/out-android/libssl.so"
echo "BORINGSSL_NOASM_BUILD_DONE"
