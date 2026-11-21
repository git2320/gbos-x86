// SPDX-License-Identifier: GPL-2.0
/*
 * Cross-check the Haswell-baseline GPR emulation against real BMI1/2, LZCNT,
 * TZCNT and MOVBE instructions. Build on a Haswell+ CPU:
 *   gcc -O2 -mbmi -mbmi2 -mlzcnt -o test_hw_gpr test_hw_gpr.c isa_emu_core.c
 *   ./test_hw_gpr
 */
#include <stdio.h>
#include <stdint.h>
#include <immintrin.h>
#include "isa_emu_core.h"

static int checks, fails;
#define CHECK(c, ...) do { checks++; if (!(c)) { fails++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static uint64_t rng = 0x9e3779b97f4a7c15ULL;
static uint64_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

/* Compare emu_grop() with the real instruction result. */
#define T32(name, op, hwval, a, b, ctrl) \
	CHECK(emu_grop((op), (a), (b), (ctrl), 4) == (u32)(hwval), \
	      "%s32 a=%08x b=%08x c=%02x: got %08x want %08x", name, (u32)(a), (u32)(b), (ctrl), \
	      (u32)emu_grop((op), (a), (b), (ctrl), 4), (u32)(hwval))
#define T64(name, op, hwval, a, b, ctrl) \
	CHECK(emu_grop((op), (a), (b), (ctrl), 8) == (u64)(hwval), \
	      "%s64 a=%016llx b=%016llx c=%02x: got %016llx want %016llx", name, \
	      (unsigned long long)(a), (unsigned long long)(b), (unsigned)(ctrl), \
	      (unsigned long long)emu_grop((op), (a), (b), (ctrl), 8), \
	      (unsigned long long)(hwval))

int main(void)
{
	int it;

	for (it = 0; it < 20000; it++) {
		u64 a = rnd(), b = rnd(), c = rnd() & 0xff;
		u32 a32 = (u32)a, b32 = (u32)b, c32 = (u32)c;

		T32("andn", EMU_G_ANDN, _andn_u32(a32, b32), a, b, 0);
		T64("andn", EMU_G_ANDN, _andn_u64(a, b), a, b, 0);

		T32("bextr", EMU_G_BEXTR, _bextr_u32(a32, c32 & 0xff, (c32 >> 8) & 0xff), a, b, c32);
		T64("bextr", EMU_G_BEXTR, _bextr_u64(a, c & 0xff, (c >> 8) & 0xff), a, b, c);

		T32("blsi", EMU_G_BLSI, _blsi_u32(a32), a, 0, 0);
		T64("blsi", EMU_G_BLSI, _blsi_u64(a), a, 0, 0);
		T32("blsmsk", EMU_G_BLSMSK, _blsmsk_u32(a32), a, 0, 0);
		T64("blsmsk", EMU_G_BLSMSK, _blsmsk_u64(a), a, 0, 0);
		T32("blsr", EMU_G_BLSR, _blsr_u32(a32), a, 0, 0);
		T64("blsr", EMU_G_BLSR, _blsr_u64(a), a, 0, 0);

		T32("bzhi", EMU_G_BZHI, _bzhi_u32(a32, c32 & 31), a, 0, c32);
		T64("bzhi", EMU_G_BZHI, _bzhi_u64(a, c & 63), a, 0, c);

		/* RORX is a plain rotate-right (no flags); gcc has no intrinsic for it. */
		{
			int n32 = c32 & 31, n64 = c & 63;
			u32 r32 = n32 ? (a32 >> n32) | (a32 << (32 - n32)) : a32;
			u64 r64 = n64 ? (a >> n64) | (a << (64 - n64)) : a;

			T32("rorx", EMU_G_RORX, r32, a, 0, c32);
			T64("rorx", EMU_G_RORX, r64, a, 0, c);
		}

		T32("lzcnt", EMU_G_LZCNT, __lzcnt32(a32), a, 0, 0);
		T64("lzcnt", EMU_G_LZCNT, __lzcnt64(a), a, 0, 0);
		T32("tzcnt", EMU_G_TZCNT, _tzcnt_u32(a32), a, 0, 0);
		T64("tzcnt", EMU_G_TZCNT, _tzcnt_u64(a), a, 0, 0);

		T32("movbe", EMU_G_MOVBE, __builtin_bswap32(a32), a, 0, 0);
		T64("movbe", EMU_G_MOVBE, __builtin_bswap64(a), a, 0, 0);
	}

	/* edge cases: zero and all-ones are where bit-scan instructions differ */
	{
		u64 v[2] = { 0, ~0ULL };
		int i;

		for (i = 0; i < 2; i++) {
			T32("lzcnt0", EMU_G_LZCNT, __lzcnt32((u32)v[i]), v[i], 0, 0);
			T64("lzcnt0", EMU_G_LZCNT, __lzcnt64(v[i]), v[i], 0, 0);
			T32("tzcnt0", EMU_G_TZCNT, _tzcnt_u32((u32)v[i]), v[i], 0, 0);
			T64("tzcnt0", EMU_G_TZCNT, _tzcnt_u64(v[i]), v[i], 0, 0);
		}
	}

	printf("%d checks, %d failures\n", checks, fails);
	return fails != 0;
}
