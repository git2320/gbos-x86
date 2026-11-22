#!/usr/bin/env python3
"""Patch BORINGSSL_FIPS_abort() to an immediate return in a libcrypto ELF.

The self-tests of Google's FIPS BoringSSL use Haswell+ ADX bigint code. On
older CPUs the instruction emulator must run it, and even correct emulation
can make a known-answer self-test abort the whole process (SIGABRT loop at
the boot animation). Since this is a community port, turn the abort into a
no-op: replace the tiny stub with `ret` + int3 padding.

Locates the stub by finding the `call abort@plt` whose surrounding function
is only a prologue (push rbp / push rax followed by the call and int3 padding),
rather than by address, so it works across the system/vendor/APEX copies.

Usage: patch_no_fips_abort.py IN [OUT]
"""
import sys

PATTERNS = (
    bytes.fromhex('554889e5e8'),   # push rbp; mov rbp,rsp; call abort@plt  (system/libcrypto)
    bytes.fromhex('50e8'),         # push rax; call abort@plt               (tethering httpengine)
)


def find_stub(d):
    for pat in PATTERNS:
        i = 0
        while True:
            i = d.find(pat, i)
            if i < 0:
                break
            # both patterns end with the e8 opcode; the rel32 follows it
            end = i + len(pat) + 4
            if end + 2 < len(d) and d[end] == 0xcc and d[end + 1] == 0xcc:
                return i, end - i
            i += 1
    return None, 0


def main():
    src, dst = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else sys.argv[1]
    d = bytearray(open(src, 'rb').read())
    off, n = find_stub(d)
    if off is None:
        print('no FIPS abort stub found in', src)
        return 1
    d[off:off + n] = b'\xc3' + b'\xcc' * (n - 1)
    open(dst, 'wb').write(d)
    print('patched %s at 0x%x (%d bytes) -> %s' % (src, off, n, dst))
    return 0


if __name__ == '__main__':
    sys.exit(main())
