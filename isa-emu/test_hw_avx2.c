// SPDX-License-Identifier: GPL-2.0
/*
 * Cross-check the AVX2 core against real hardware. Build on a Haswell+ CPU:
 *   gcc -O2 -mavx2 -mbmi -mbmi2 -o test_hw_avx2 test_hw_avx2.c isa_emu_core.c
 *   ./test_hw_avx2
 * Every case executes the real instruction with intrinsics and compares the
 * result with emu_vop(), i.e. with the code a pre-Haswell CPU relies on.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <immintrin.h>
#include "isa_emu_core.h"

static int checks, fails;
#define CHECK(c, ...) do { checks++; if (!(c)) { fails++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static uint64_t rng = 0x243f6a8885a308d3ULL;
static uint64_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }
static void rndbuf(u8 *p, int n) { int i; for (i = 0; i < n; i++) p[i] = (u8)(rnd() >> 24); }

static __m256i ld(const u8 *p) { return _mm256_loadu_si256((const __m256i *)p); }
static void st(u8 *p, __m256i v) { _mm256_storeu_si256((__m256i *)p, v); }

/* hw = result of the real instruction; sw = result of our scalar emulator. */
#define CMP(name) CHECK(!memcmp(hw, sw, 32), "%s", name)

int main(void)
{
	u8 a[32], b[32], hw[32], sw[32];
	int i, it;

	isa_emu_core_init();

	/* broadcasts: the source is the low 1/2/4/8 bytes of the r/m operand */
	for (it = 0; it < 100; it++) {
		rndbuf(a, 32); rndbuf(b, 32);
		st(hw, _mm256_set1_epi8((char)b[0]));
		emu_vop(sw, a, b, 32, 1, EMU_V_BROADCAST, 1); CMP("vpbroadcastb");
		{
			u16 v; memcpy(&v, b, 2); st(hw, _mm256_set1_epi16((short)v));
		}
		emu_vop(sw, a, b, 32, 2, EMU_V_BROADCAST, 2); CMP("vpbroadcastw");
		{
			u32 v; memcpy(&v, b, 4); st(hw, _mm256_set1_epi32((int)v));
		}
		emu_vop(sw, a, b, 32, 4, EMU_V_BROADCAST, 4); CMP("vpbroadcastd");
		{
			u64 v; memcpy(&v, b, 8); st(hw, _mm256_set1_epi64x((long long)v));
		}
		emu_vop(sw, a, b, 32, 8, EMU_V_BROADCAST, 8); CMP("vpbroadcastq");
	}

	for (it = 0; it < 200; it++) {
		rndbuf(a, 32); rndbuf(b, 32);

		st(hw, _mm256_xor_si256(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 1, EMU_V_XOR, 0); CMP("vpxor");
		st(hw, _mm256_or_si256(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 1, EMU_V_OR, 0); CMP("vpor");
		st(hw, _mm256_and_si256(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 1, EMU_V_AND, 0); CMP("vpand");
		st(hw, _mm256_andnot_si256(ld(b), ld(a)));
		emu_vop(sw, a, b, 32, 1, EMU_V_ANDN, 0); CMP("vpandn");

		st(hw, _mm256_add_epi8(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 1, EMU_V_ADD, 0); CMP("vpaddb");
		st(hw, _mm256_add_epi16(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 2, EMU_V_ADD, 0); CMP("vpaddw");
		st(hw, _mm256_add_epi32(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 4, EMU_V_ADD, 0); CMP("vpaddd");
		st(hw, _mm256_add_epi64(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 8, EMU_V_ADD, 0); CMP("vpaddq");
		st(hw, _mm256_sub_epi32(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 4, EMU_V_SUB, 0); CMP("vpsubd");

		st(hw, _mm256_adds_epi8(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 1, EMU_V_ADDS_S, 0); CMP("vpaddsb");
		st(hw, _mm256_subs_epi8(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 1, EMU_V_SUBS_S, 0); CMP("vpsubsb");
		st(hw, _mm256_adds_epu8(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 1, EMU_V_ADDS_U, 0); CMP("vpaddusb");
		st(hw, _mm256_subs_epu8(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 1, EMU_V_SUBS_U, 0); CMP("vpsubusb");

		st(hw, _mm256_cmpeq_epi8(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 1, EMU_V_EQ, 0); CMP("vpcmpeqb");
		st(hw, _mm256_cmpgt_epi32(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 4, EMU_V_GT, 0); CMP("vpcmpgtd");
		st(hw, _mm256_cmpgt_epi64(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 8, EMU_V_GT, 0); CMP("vpcmpgtq");

		st(hw, _mm256_min_epi8(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 1, EMU_V_MIN_S, 0); CMP("vpminsb");
		st(hw, _mm256_max_epi32(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 4, EMU_V_MAX_S, 0); CMP("vpmaxsd");
		st(hw, _mm256_min_epu16(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 2, EMU_V_MIN_U, 0); CMP("vpminuw");
		st(hw, _mm256_max_epu32(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 4, EMU_V_MAX_U, 0); CMP("vpmaxud");

		st(hw, _mm256_slli_epi32(ld(a), 7));
		emu_vop(sw, a, a, 32, 4, EMU_V_SLL, 7); CMP("vpslld imm");
		st(hw, _mm256_srai_epi32(ld(a), 7));
		emu_vop(sw, a, a, 32, 4, EMU_V_SRA, 7); CMP("vpsrad imm");
		st(hw, _mm256_srlv_epi32(ld(a), ld(b)));
		emu_vshift_var(sw, a, b, 32, 4, 1); CMP("vpsrlvd");
		st(hw, _mm256_srav_epi32(ld(a), ld(b)));
		emu_vshift_var(sw, a, b, 32, 4, 2); CMP("vpsravd");

		st(hw, _mm256_shuffle_epi8(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 1, EMU_V_SHUFB, 0); CMP("vpshufb");
		st(hw, _mm256_alignr_epi8(ld(a), ld(b), 5));
		emu_vop(sw, a, b, 32, 1, EMU_V_ALIGNR, 5); CMP("vpalignr");

		st(hw, _mm256_unpacklo_epi32(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 4, EMU_V_UNPCKL, 0); CMP("vpunpckldq");
		st(hw, _mm256_unpackhi_epi16(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 2, EMU_V_UNPCKH, 0); CMP("vpunpckhwd");
		st(hw, _mm256_packus_epi16(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 2, EMU_V_PACKUS, 0); CMP("vpackuswb");

		{
			int m = _mm256_movemask_epi8(ld(a));
			memcpy(hw, &m, 4);
		}
		emu_vop(sw, a, a, 32, 1, EMU_V_MOVMSK, 0);
		CHECK(!memcmp(hw, sw, 4), "vpmovmskb");

		st(hw, _mm256_cvtepi8_epi16(_mm_loadu_si128((const __m128i *)a)));
		emu_vop(sw, a, a, 32, 2, EMU_V_MOVSX, 1); CMP("vpmovsxbw");
		st(hw, _mm256_cvtepu8_epi32(_mm_loadu_si128((const __m128i *)a)));
		emu_vop(sw, a, a, 32, 4, EMU_V_MOVZX, 1); CMP("vpmovzxbd");

		st(hw, _mm256_permute4x64_epi64(ld(a), 0x1b));
		emu_vop(sw, a, a, 32, 8, EMU_V_PERMQ, 0x1b); CMP("vpermq");
		st(hw, _mm256_permute2x128_si256(ld(a), ld(b), 0x21));
		emu_vop(sw, a, b, 32, 16, EMU_V_PERM2I128, 0x21); CMP("vperm2i128");

		st(hw, _mm256_madd_epi16(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 4, EMU_V_MULADD, 0); CMP("vpmaddwd");
		st(hw, _mm256_sad_epu8(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 8, EMU_V_SAD, 0); CMP("vpsadbw");
		st(hw, _mm256_mullo_epi32(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 4, EMU_V_MUL, 0); CMP("vpmulld");
		st(hw, _mm256_mulhi_epu16(ld(a), ld(b)));
		emu_vop(sw, a, b, 32, 2, EMU_V_MULHI, 0); CMP("vpmulhuw");

		st(hw, _mm256_abs_epi16(ld(a)));
		emu_vop(sw, a, a, 32, 2, EMU_V_ABS, 0); CMP("vpabsw");
		st(hw, _mm256_blend_epi32(ld(a), ld(b), 0xa5));
		emu_vop(sw, a, b, 32, 4, EMU_V_BLEND, 0xa5); CMP("vblendps");
		st(hw, _mm256_castps_si256(_mm256_permute_ps(_mm256_castsi256_ps(ld(a)), 0x1b)));
		emu_vop(sw, a, a, 32, 4, EMU_V_PERMILPS, 0x1b); CMP("vpermilps imm");
	}

	/* float conversions: use simple values so rounding modes cannot differ */
	for (i = 0; i < 8; i++) {
		float f = (float)(i - 3);
		memcpy(a + 4 * i, &f, 4);
	}
	{
		__m256 v = _mm256_loadu_ps((const float *)a);

		st(hw, _mm256_cvttps_epi32(v));
		emu_vop(sw, a, a, 32, 4, EMU_V_CVTTPS2DQ, 0); CMP("cvttps2dq");
		st(hw, _mm256_cvtps_epi32(v));
		emu_vop(sw, a, a, 32, 4, EMU_V_CVTPS2DQ, 0); CMP("cvtps2dq");
	}

	printf("%d checks, %d failures\n", checks, fails);
	return fails != 0;
}
