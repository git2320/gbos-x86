// SPDX-License-Identifier: GPL-2.0
/*
 * Software implementations of GFNI, AVX-VNNI, SHA-NI, VAES, VPCLMULQDQ and
 * AVX-IFMA, following the pseudocode in the Intel SDM. See isa_emu_core.h.
 */
#include "isa_emu_core.h"
#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

static inline u32 ld32(const u8 *p, int i)
{
	p += 4 * i;
	return (u32)p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24;
}

static inline void st32(u8 *p, int i, u32 v)
{
	p += 4 * i;
	p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}

static inline u32 rol32(u32 v, int n) { return (v << n) | (v >> (32 - n)); }
static inline u32 ror32(u32 v, int n) { return (v >> n) | (v << (32 - n)); }

/* ---- GFNI ---------------------------------------------------------------- */

/* Multiply in GF(2^8) with the AES reduction polynomial x^8 + x^4 + x^3 + x + 1. */
static u8 gf_mul(u8 a, u8 b)
{
	u8 r = 0;

	while (b) {
		if (b & 1)
			r ^= a;
		a = (a << 1) ^ ((a & 0x80) ? 0x1b : 0);
		b >>= 1;
	}
	return r;
}

/* Multiplicative inverse; the instruction defines inverse(0) as 0. x^254 = x^-1. */
static u8 gf_inv(u8 x)
{
	u8 r = 1, p = x;
	int e = 254;

	if (!x)
		return 0;
	while (e) {
		if (e & 1)
			r = gf_mul(r, p);
		p = gf_mul(p, p);
		e >>= 1;
	}
	return r;
}

static inline int parity8(u8 v)
{
	v ^= v >> 4;
	v ^= v >> 2;
	v ^= v >> 1;
	return v & 1;
}

static u8 affine_byte(const u8 *matrix_qword, u8 x, u8 imm)
{
	u8 r = 0;
	int i;

	for (i = 0; i < 8; i++)
		r |= (parity8(matrix_qword[7 - i] & x) ^ ((imm >> i) & 1)) << i;
	return r;
}

void emu_gf2p8affineqb(u8 *dst, const u8 *x, const u8 *m, u8 imm, int len)
{
	u8 out[32];
	int i;

	for (i = 0; i < len; i++)
		out[i] = affine_byte(m + (i & ~7), x[i], imm);
	for (i = 0; i < len; i++)
		dst[i] = out[i];
}

void emu_gf2p8affineinvqb(u8 *dst, const u8 *x, const u8 *m, u8 imm, int len)
{
	u8 out[32];
	int i;

	for (i = 0; i < len; i++)
		out[i] = affine_byte(m + (i & ~7), gf_inv(x[i]), imm);
	for (i = 0; i < len; i++)
		dst[i] = out[i];
}

void emu_gf2p8mulb(u8 *dst, const u8 *a, const u8 *b, int len)
{
	u8 out[32];
	int i;

	for (i = 0; i < len; i++)
		out[i] = gf_mul(a[i], b[i]);
	for (i = 0; i < len; i++)
		dst[i] = out[i];
}

/* ---- AVX-VNNI -------------------------------------------------------------- */

static u32 sat32(s64 v)
{
	if (v > 0x7fffffffLL)
		return 0x7fffffff;
	if (v < -0x80000000LL)
		return 0x80000000u;
	return (u32)v;
}

void emu_vpdpbusd(u8 *acc, const u8 *a, const u8 *b, int len, int saturate)
{
	int i, k;

	for (i = 0; i < len / 4; i++) {
		s64 sum = 0;

		for (k = 0; k < 4; k++)
			sum += (s64)a[4 * i + k] * (s8)b[4 * i + k]; /* unsigned x signed */
		if (saturate)
			st32(acc, i, sat32((s64)(s32)ld32(acc, i) + sum));
		else
			st32(acc, i, ld32(acc, i) + (u32)sum);
	}
}

void emu_vpdpwssd(u8 *acc, const u8 *a, const u8 *b, int len, int saturate)
{
	int i, k;

	for (i = 0; i < len / 4; i++) {
		s64 sum = 0;

		for (k = 0; k < 2; k++) {
			s16 x = (s16)(a[4 * i + 2 * k] | a[4 * i + 2 * k + 1] << 8);
			s16 y = (s16)(b[4 * i + 2 * k] | b[4 * i + 2 * k + 1] << 8);

			sum += (s64)x * y;
		}
		if (saturate)
			st32(acc, i, sat32((s64)(s32)ld32(acc, i) + sum));
		else
			st32(acc, i, ld32(acc, i) + (u32)sum);
	}
}

void emu_vpdp8(u8 *acc, const u8 *a, const u8 *b, int len, int saturate, int a_signed, int b_signed)
{
	int i, k;

	for (i = 0; i < len / 4; i++) {
		s64 sum = 0;

		for (k = 0; k < 4; k++) {
			s64 x = a_signed ? (s64)(s8)a[4 * i + k] : (s64)a[4 * i + k];
			s64 y = b_signed ? (s64)(s8)b[4 * i + k] : (s64)b[4 * i + k];

			sum += x * y;
		}
		if (saturate)
			st32(acc, i, sat32((s64)(s32)ld32(acc, i) + sum));
		else
			st32(acc, i, ld32(acc, i) + (u32)sum);
	}
}

/* ---- AVX-IFMA -------------------------------------------------------------- */

static inline u64 ld64(const u8 *p, int i)
{
	return (u64)ld32(p, 2 * i) | (u64)ld32(p, 2 * i + 1) << 32;
}

static inline void st64(u8 *p, int i, u64 v)
{
	st32(p, 2 * i, (u32)v);
	st32(p, 2 * i + 1, (u32)(v >> 32));
}

void emu_vpmadd52(u8 *acc, const u8 *a, const u8 *b, int len, int high)
{
	const u64 m52 = (1ULL << 52) - 1;
	int i;

	for (i = 0; i < len / 8; i++) {
		unsigned __int128 p = (unsigned __int128)(ld64(a, i) & m52) * (ld64(b, i) & m52);
		u64 r = high ? (u64)(p >> 52) & m52 : (u64)p & m52;

		st64(acc, i, ld64(acc, i) + r);
	}
}

/* ---- AES (VAES) ------------------------------------------------------------ */

static u8 aes_sbox[256], aes_isbox[256];
static int aes_ready;

void isa_emu_core_init(void)
{
	int x;

	if (aes_ready)
		return;
	for (x = 0; x < 256; x++) {
		u8 b = gf_inv((u8)x);
		u8 s = b ^ (u8)((b << 1) | (b >> 7)) ^ (u8)((b << 2) | (b >> 6)) ^
		       (u8)((b << 3) | (b >> 5)) ^ (u8)((b << 4) | (b >> 4)) ^ 0x63;

		aes_sbox[x] = s;
		aes_isbox[s] = (u8)x;
	}
	aes_ready = 1;
}

static void aes_lane(u8 *out, const u8 *in, const u8 *rk, int op)
{
	u8 s[16], t[16];
	int inv = op >= EMU_AESDEC, last = op == EMU_AESENCLAST || op == EMU_AESDECLAST;
	int r, c, i;

	for (i = 0; i < 16; i++)
		s[i] = in[i];
	/* (Inv)ShiftRows: state byte index = row + 4 * column */
	for (c = 0; c < 4; c++)
		for (r = 0; r < 4; r++)
			t[r + 4 * c] = s[r + 4 * ((c + (inv ? 4 - r : r)) & 3)];
	for (i = 0; i < 16; i++)
		t[i] = inv ? aes_isbox[t[i]] : aes_sbox[t[i]];
	if (!last) {
		for (c = 0; c < 4; c++) {
			u8 *col = t + 4 * c, a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];

			if (!inv) {
				col[0] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
				col[1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
				col[2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
				col[3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
			} else {
				col[0] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
				col[1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
				col[2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
				col[3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
			}
		}
	}
	for (i = 0; i < 16; i++)
		out[i] = t[i] ^ rk[i];
}

void emu_vaes(u8 *dst, const u8 *state, const u8 *rk, int len, int op)
{
	u8 out[32];
	int l;

	for (l = 0; l < len / 16; l++)
		aes_lane(out + 16 * l, state + 16 * l, rk + 16 * l, op);
	for (l = 0; l < len; l++)
		dst[l] = out[l];
}

/* ---- VPCLMULQDQ ------------------------------------------------------------ */

void emu_vpclmulqdq(u8 *dst, const u8 *a, const u8 *b, u8 imm, int len)
{
	u8 out[32];
	int l, i;

	for (l = 0; l < len / 16; l++) {
		u64 x = ld64(a + 16 * l, imm & 1 ? 1 : 0), y = ld64(b + 16 * l, imm & 0x10 ? 1 : 0);
		u64 lo = 0, hi = 0;

		for (i = 0; i < 64; i++) {
			if ((y >> i) & 1) {
				lo ^= x << i;
				if (i)
					hi ^= x >> (64 - i);
			}
		}
		st64(out + 16 * l, 0, lo);
		st64(out + 16 * l, 1, hi);
	}
	for (i = 0; i < len; i++)
		dst[i] = out[i];
}

/* ---- SHA-NI ---------------------------------------------------------------- */
/* Dword index 3 is bits 127:96, index 0 is bits 31:0. */

static u32 sha1_f(int fn, u32 b, u32 c, u32 d)
{
	switch (fn) {
	case 0: return (b & c) ^ (~b & d);
	case 2: return (b & c) ^ (b & d) ^ (c & d);
	default: return b ^ c ^ d;
	}
}

void emu_sha1rnds4(u8 *dst, const u8 *src, u8 imm)
{
	static const u32 K[4] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };
	u32 a = ld32(dst, 3), b = ld32(dst, 2), c = ld32(dst, 1), d = ld32(dst, 0), e = 0;
	u32 w[4] = { ld32(src, 3), ld32(src, 2), ld32(src, 1), ld32(src, 0) };
	int fn = imm & 3, i;

	for (i = 0; i < 4; i++) {
		u32 t = sha1_f(fn, b, c, d) + rol32(a, 5) + w[i] + e + K[fn];

		e = d; d = c; c = rol32(b, 30); b = a; a = t;
	}
	st32(dst, 3, a); st32(dst, 2, b); st32(dst, 1, c); st32(dst, 0, d);
}

void emu_sha1nexte(u8 *dst, const u8 *src)
{
	u32 t = rol32(ld32(dst, 3), 30);
	int i;

	for (i = 0; i < 3; i++)
		st32(dst, i, ld32(src, i));
	st32(dst, 3, ld32(src, 3) + t);
}

void emu_sha1msg1(u8 *dst, const u8 *src)
{
	u32 w0 = ld32(dst, 3), w1 = ld32(dst, 2), w2 = ld32(dst, 1), w3 = ld32(dst, 0);
	u32 w4 = ld32(src, 3), w5 = ld32(src, 2);

	st32(dst, 3, w2 ^ w0); st32(dst, 2, w3 ^ w1);
	st32(dst, 1, w4 ^ w2); st32(dst, 0, w5 ^ w3);
}

void emu_sha1msg2(u8 *dst, const u8 *src)
{
	u32 w13 = ld32(src, 2), w14 = ld32(src, 1), w15 = ld32(src, 0);
	u32 w16 = rol32(ld32(dst, 3) ^ w13, 1);
	u32 w17 = rol32(ld32(dst, 2) ^ w14, 1);
	u32 w18 = rol32(ld32(dst, 1) ^ w15, 1);
	u32 w19 = rol32(ld32(dst, 0) ^ w16, 1);

	st32(dst, 3, w16); st32(dst, 2, w17); st32(dst, 1, w18); st32(dst, 0, w19);
}

void emu_sha256rnds2(u8 *dst, const u8 *src, const u8 *xmm0)
{
	u32 a = ld32(src, 3), b = ld32(src, 2), c = ld32(dst, 3), d = ld32(dst, 2);
	u32 e = ld32(src, 1), f = ld32(src, 0), g = ld32(dst, 1), h = ld32(dst, 0);
	u32 wk[2] = { ld32(xmm0, 0), ld32(xmm0, 1) };
	u32 an[2], en[2];
	int i;

	for (i = 0; i < 2; i++) {
		u32 ch = (e & f) ^ (~e & g);
		u32 maj = (a & b) ^ (a & c) ^ (b & c);
		u32 s0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
		u32 s1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
		u32 t = ch + s1 + wk[i] + h;

		an[i] = t + maj + s0;
		en[i] = t + d;
		h = g; g = f; f = e; e = en[i];
		d = c; c = b; b = a; a = an[i];
	}
	st32(dst, 3, an[1]); st32(dst, 2, an[0]); st32(dst, 1, en[1]); st32(dst, 0, en[0]);
}

static u32 sig0(u32 x) { return ror32(x, 7) ^ ror32(x, 18) ^ (x >> 3); }
static u32 sig1(u32 x) { return ror32(x, 17) ^ ror32(x, 19) ^ (x >> 10); }

void emu_sha256msg1(u8 *dst, const u8 *src)
{
	u32 w4 = ld32(src, 0), w3 = ld32(dst, 3), w2 = ld32(dst, 2), w1 = ld32(dst, 1), w0 = ld32(dst, 0);

	st32(dst, 3, w3 + sig0(w4)); st32(dst, 2, w2 + sig0(w3));
	st32(dst, 1, w1 + sig0(w2)); st32(dst, 0, w0 + sig0(w1));
}

void emu_sha256msg2(u8 *dst, const u8 *src)
{
	u32 w14 = ld32(src, 2), w15 = ld32(src, 3);
	u32 w16 = ld32(dst, 0) + sig1(w14);
	u32 w17 = ld32(dst, 1) + sig1(w15);
	u32 w18 = ld32(dst, 2) + sig1(w16);
	u32 w19 = ld32(dst, 3) + sig1(w17);

	st32(dst, 3, w19); st32(dst, 2, w18); st32(dst, 1, w17); st32(dst, 0, w16);
}

/* ---- AVX/AVX2 baseline, for CPUs with AVX but no AVX2 (Sandy/Ivy Bridge) --- */

static inline u64 ldN(const u8 *p, int n)
{
	u64 v = 0;
	int i;

	for (i = 0; i < n; i++)
		v |= (u64)p[i] << (8 * i);
	return v;
}

static inline void stN(u8 *p, int n, u64 v)
{
	int i;

	for (i = 0; i < n; i++)
		p[i] = (u8)(v >> (8 * i));
}

static inline u64 maskN(int n)
{
	return n == 8 ? ~0ULL : (1ULL << (8 * n)) - 1;
}

static inline s64 sxN(u64 v, int n)
{
	return n == 8 ? (s64)v : (s64)(v << (64 - 8 * n)) >> (64 - 8 * n);
}

static inline s64 sat_s(s64 v, int n)
{
	s64 lo = n == 8 ? (s64)0x8000000000000000ULL : -(1LL << (8 * n - 1));
	s64 hi = n == 8 ? 0x7fffffffffffffffLL : (1LL << (8 * n - 1)) - 1;

	return v < lo ? lo : v > hi ? hi : v;
}

static inline u64 sat_u(u64 v, int n)
{
	u64 hi = maskN(n);

	return v > hi ? hi : v;
}

/* dst += signed 16-bit a * signed 16-bit b, summed in pairs into dwords. */
static void pmaddwd(u8 *dst, const u8 *a, const u8 *b, int len)
{
	int i, j;

	for (i = 0; i < len / 4; i++) {
		s32 p = 0;

		for (j = 0; j < 2; j++)
			p += (s16)ldN(a + 4 * i + 2 * j, 2) * (s16)ldN(b + 4 * i + 2 * j, 2);
		stN(dst + 4 * i, 4, (u32)p);
	}
}

/* SAD: per qword lane, sum of |a byte - b byte|, result in the low 16 bits. */
static void psadbw(u8 *dst, const u8 *a, const u8 *b, int len)
{
	int l, i;

	for (l = 0; l < len / 8; l++) {
		u32 s = 0;

		for (i = 0; i < 8; i++)
			s += a[8 * l + i] > b[8 * l + i] ? a[8 * l + i] - b[8 * l + i]
							     : b[8 * l + i] - a[8 * l + i];
		stN(dst + 8 * l, 8, s & 0xffff);
	}
}

/* Truncate/round the low 32-bit floats of a to signed dwords (CVTTPS2DQ/CVTPS2DQ). */
static void cvtps2dq(u8 *dst, const u8 *a, int len, int round)
{
	int i;

	for (i = 0; i < len / 4; i++) {
		u32 f = (u32)ldN(a + 4 * i, 4);
		u32 m = f & 0x7fffff;
		int e = (f >> 23) & 0xff;
		s64 v = 0x80000000;

		if (e < 0xff) {
			u64 sig = e ? (m | 0x800000) : m;
			int sh = e - 127 - 23;

			if (!e)
				v = 0;		/* zero or subnormal converts to +0/-0 */

			if (sh >= 32)
				v = 0x80000000;		/* overflow: indefinite integer */
			else if (sh >= 0)
				v = e ? (s64)(sig << sh) : 0;
			else if (sh > -32)
				v = sig >> -sh;
			if (round && sh < 0 && sh > -32) {
				u32 rem = sig & ((1U << -sh) - 1);
				u32 half = 1U << (-sh - 1);

				if (rem > half || (rem == half && (sig & (1ULL << -sh))))
					v++;
			}
			if (f >> 31)
				v = -v;
		}
		stN(dst + 4 * i, 4, (u32)v);
	}
}

static void cvtpd2ps(u8 *dst, const u8 *a, int len)
{
	int i;

	for (i = 0; i < len / 8; i++) {
		u64 d = ldN(a + 8 * i, 8);
		u32 sign = (u32)(d >> 31) & 0x80000000;
		int e = (int)((d >> 52) & 0x7ff);
		u64 m = d & ((1ULL << 52) - 1);
		u32 f;

		if (e == 0x7ff)
			f = sign | 0x7f800000 | (u32)(m >> 29);
		else if (e == 0)
			f = sign;
		else if (e > 1023 + 127)
			f = sign | 0x7f800000;
		else if (e < 1023 - 126)
			f = sign;
		else
			f = sign | (u32)((e - 1023 + 127) << 23) | (u32)(m >> 29);
		stN(dst + 4 * i, 4, f);
	}
}

void emu_vop(u8 *dst, const u8 *a, const u8 *b, int len, int elem, enum emu_vop op, int aux)
{
	int i, l, n, lane;

	/* Never divide by a zero element size: a bad decode must not panic the kernel. */
	if (elem <= 0 || len < 16)
		return;
	n = len / elem;
	lane = len / 16;

	switch (op) {
	case EMU_V_MOV:
		/* Move is a raw vector copy; elem is irrelevant and may be len-sized. */
		memcpy(dst, b, len);
		return;
	case EMU_V_BROADCAST:
		/* The source is the r/m operand, which do_emulate() loads into b. */
		for (i = 0; i < n; i++)
			stN(dst + i * elem, elem, ldN(b, aux));
		return;
	case EMU_V_MOVSX:
	case EMU_V_MOVZX:
		/* vpmovsx/zx: number of output elements is len/elem (e.g. vpmovsxbq writes
		 * 4 qwords from 4 source bytes, not 16 bytes worth of results). */
		for (i = 0; i < n; i++) {
			u64 v = ldN(a + aux * i, aux);

			if (op == EMU_V_MOVSX)
				v = (u64)sxN(v, aux);
			stN(dst + elem * i, elem, v & maskN(elem));
		}
		return;
	case EMU_V_MOVMSK: {
		u32 m = 0;

		for (i = 0; i < n; i++)
			if (ldN(a + i * elem, elem) >> (8 * elem - 1))
				m |= 1u << i;
		st32(dst, 0, m);
		return;
	}
	case EMU_V_PERMQ:
		for (i = 0; i < 4; i++)
			stN(dst + 8 * i, 8, ldN(a + 8 * ((aux >> (2 * i)) & 3), 8));
		return;
	case EMU_V_PERM2I128:
		for (i = 0; i < 2; i++) {
			int src = (aux >> (4 * i)) & 3;
			/* 0/1 select a's lanes, 2/3 b's lanes. With one vector source (VEX.128
			 * form of vperm2i128 is not used here) a and b are the same image. */
			memcpy(dst + 16 * i, (src >= 2 ? b : a) + 16 * (src & 1), 16);
		}
		return;
	case EMU_V_PERMILPS:
		for (l = 0; l < lane; l++)
			for (i = 0; i < 4; i++) {
				int sel = (aux >> (2 * i)) & 3;
				u8 tmp[32];

				/* Variable form (aux = -1) takes selectors from b. */
				if (aux < 0)
					sel = ldN(b + 16 * l + 4 * i, 4) & 3;
				memcpy(tmp + 4 * i, a + 16 * l + 4 * sel, 4);
				memcpy(dst + 16 * l, tmp, 16);
			}
		return;
	case EMU_V_PERMILPD:
		for (l = 0; l < lane; l++)
			for (i = 0; i < 2; i++) {
				int sel = (aux >> (i + 1)) & 1;
				u8 tmp[16];

				if (aux < 0)
					sel = ldN(b + 16 * l + 8 * i, 8) >> 1 & 1;
				memcpy(tmp + 8 * i, a + 16 * l + 8 * sel, 8);
				memcpy(dst + 16 * l, tmp, 16);
			}
		return;
	case EMU_V_SHUFB:
		for (l = 0; l < lane; l++)
			for (i = 0; i < 16; i++)
				dst[16 * l + i] = (b[16 * l + i] & 0x80) ? 0 : a[16 * l + (b[16 * l + i] & 0xf)];
		return;
	case EMU_V_ALIGNR:
		for (l = 0; l < lane; l++)
			for (i = 0; i < 16; i++) {
				int s = i + (aux & 15);

				dst[16 * l + i] = s < 16 ? b[16 * l + s] : a[16 * l + s - 16];
			}
		return;
	case EMU_V_UNPCKL:
	case EMU_V_UNPCKH: {
		int half_n = n / 2 / lane, off = op == EMU_V_UNPCKH ? half_n : 0;

		for (l = 0; l < lane; l++)
			for (i = 0; i < half_n; i++) {
				u8 *d = dst + 16 * l + i * 2 * elem;

				memcpy(d, a + 16 * l + (off + i) * elem, elem);
				memcpy(d + elem, b + 16 * l + (off + i) * elem, elem);
			}
		return;
	}
	case EMU_V_PACKUS: {
		int out = elem / 2, cnt = 16 / elem;

		for (l = 0; l < lane; l++)
			for (i = 0; i < cnt; i++) {
				s64 x = sxN(ldN(a + 16 * l + i * elem, elem), elem);
				u64 lo = x < 0 ? 0 : (u64)x > maskN(out) ? maskN(out) : (u64)x;

				/* All source elements of a come first, then all of b, per lane. */
				stN(dst + 16 * l + i * out, out, lo);
			}
		for (l = 0; l < lane; l++)
			for (i = 0; i < cnt; i++) {
				s64 y = sxN(ldN(b + 16 * l + i * elem, elem), elem);
				u64 hi = y < 0 ? 0 : (u64)y > maskN(out) ? maskN(out) : (u64)y;

				stN(dst + 16 * l + (cnt + i) * out, out, hi);
			}
		return;
	}
	case EMU_V_MULADD:
		pmaddwd(dst, a, b, len);
		return;
	case EMU_V_SAD:
		psadbw(dst, a, b, len);
		return;
	case EMU_V_BLEND: {
		int per = 16 / elem;	/* selector bits per 128-bit lane */

		for (i = 0; i < n; i++) {
			int lane_i = (i * elem) / 16, idx = ((i * elem) % 16) / elem;
			int bit = (aux >> (lane_i * per + idx)) & 1;

			memcpy(dst + i * elem, (bit ? b : a) + i * elem, elem);
		}
		return;
	}
	case EMU_V_CVTTPS2DQ:
	case EMU_V_CVTPS2DQ:
		cvtps2dq(dst, a, len, op == EMU_V_CVTPS2DQ);
		return;
	case EMU_V_CVTPD2PS:
		cvtpd2ps(dst, a, len);
		return;
	default:
		break;
	}

	/* Per-element binary (or unary, for ABS) operations. */
	for (i = 0; i < n; i++) {
		u64 av = ldN(a + i * elem, elem), bv = ldN(b + i * elem, elem);
		s64 sa = sxN(av, elem), sb = sxN(bv, elem);
		u64 r = 0;

		switch (op) {
		case EMU_V_MOV:	r = bv; break;
		case EMU_V_AND:	r = av & bv; break;
		case EMU_V_OR:	r = av | bv; break;
		case EMU_V_XOR:	r = av ^ bv; break;
		case EMU_V_ANDN: r = av & ~bv; break;
		case EMU_V_ADD:	r = av + bv; break;
		case EMU_V_SUB:	r = av - bv; break;
		case EMU_V_ADDS_S: r = (u64)sat_s(sa + sb, elem); break;
		case EMU_V_SUBS_S: r = (u64)sat_s(sa - sb, elem); break;
		case EMU_V_ADDS_U: r = sat_u(av + bv, elem); break;
		case EMU_V_SUBS_U: r = av > bv ? av - bv : 0; break;
		case EMU_V_EQ:	r = sa == sb ? maskN(elem) : 0; break;
		case EMU_V_GT:	r = sa > sb ? maskN(elem) : 0; break;
		case EMU_V_MIN_S: r = (u64)(sa < sb ? sa : sb); break;
		case EMU_V_MAX_S: r = (u64)(sa > sb ? sa : sb); break;
		case EMU_V_MIN_U: r = av < bv ? av : bv; break;
		case EMU_V_MAX_U: r = av > bv ? av : bv; break;
		case EMU_V_SLL: r = aux >= elem * 8 ? 0 : av << aux; break;
		case EMU_V_SRL: r = aux >= elem * 8 ? 0 : av >> aux; break;
		case EMU_V_SRA: r = (u64)(aux >= elem * 8 ? (sa >> (elem * 8 - 1)) : (sa >> aux)); break;
		case EMU_V_MUL:
			if (elem == 8)
				r = (u64)((s64)av * (s64)bv);
			else if (elem == 4)
				r = (u32)((s32)(u32)av * (s32)(u32)bv);
			else
				r = (u16)((s16)(u16)av * (s16)(u16)bv);
			break;
		case EMU_V_MULHI: r = ((u64)(u16)av * (u16)bv) >> 16; break;
		case EMU_V_ABS: r = (u64)(sa < 0 ? -sa : sa); break;
		case EMU_V_SIGN:
			r = sb < 0 ? (u64)(sa < 0 ? -sa : sa) : sb == 0 ? 0 : av;
			break;
		default: return;
		}
		stN(dst + i * elem, elem, r & maskN(elem));
	}
}

void emu_vshift_var(u8 *dst, const u8 *a, const u8 *b, int len, int elem, int kind)
{
	int i, n;

	if (elem <= 0 || len < 16)
		return;
	n = len / elem;

	for (i = 0; i < n; i++) {
		u64 av = ldN(a + i * elem, elem), cnt = ldN(b + i * elem, elem);
		s64 sa = sxN(av, elem);
		u64 r;

		/* AVX2 variable shifts do NOT mask the count: >= width gives zero/sign fill. */
		if (cnt >= (u64)elem * 8)
			r = kind == 2 ? (u64)(sa >> (elem * 8 - 1)) : 0;
		else if (kind == 0)
			r = av << cnt;
		else if (kind == 1)
			r = av >> cnt;
		else
			r = (u64)(sa >> cnt);
		stN(dst + i * elem, elem, r & maskN(elem));
	}
}

void emu_vmovmsk(u8 *dst, const u8 *a, int len, int elem)
{
	emu_vop(dst, a, a, len, elem, EMU_V_MOVMSK, 0);
}

/* ---- Haswell-baseline GPR instructions ---------------------------------- */
u64 emu_grop(enum emu_grop op, u64 a, u64 b, u32 ctrl, int width)
{
	u64 r = 0, mask = width == 8 ? ~0ULL : 0xffffffffULL;
	int n = width * 8, i;

	a &= mask;
	b &= mask;

	switch (op) {
	case EMU_G_ANDN:
		r = ~a & b;
		break;
	case EMU_G_BEXTR: {
		u32 start = ctrl & 0xff, len = (ctrl >> 8) & 0xff;
		u64 bits = len >= 64 ? ~0ULL : (1ULL << len) - 1;

		r = start >= (u32)n ? 0 : (a >> start) & bits;
		break;
	}
	case EMU_G_BLSI:   r = a & -a; break;
	case EMU_G_BLSMSK: r = a ^ (a - 1); break;
	case EMU_G_BLSR:   r = a & (a - 1); break;
	case EMU_G_BZHI: {
		int hi = ctrl & (width == 8 ? 63 : 31);

		/* index 0 clears every bit: a & ((1 << 0) - 1) == 0. */
		r = a & ((1ULL << hi) - 1);
		break;
	}
	case EMU_G_RORX: {
		int cnt = width == 8 ? (ctrl & 63) : (ctrl & 31);

		if (!cnt)
			r = a;
		else if (width == 8)
			r = (a >> cnt) | (a << (64 - cnt));
		else {
			u32 x = (u32)a;

			r = (x >> cnt) | (x << (32 - cnt));
		}
		break;
	}
	case EMU_G_LZCNT:
		while (n && !(a & (1ULL << (n - 1)))) { r++; n--; }
		break;
	case EMU_G_TZCNT:
		if (!a)
			r = n;
		else
			while (!(a & 1)) { r++; a >>= 1; }
		break;
	case EMU_G_MOVBE: {
		u8 tmp[8], out[8];

		for (i = 0; i < width; i++)
			out[i] = ((const u8 *)&a)[width - 1 - i];
		memcpy(tmp, out, width);
		memcpy(&r, tmp, width);
		break;
	}
	}
	return r & mask;
}

/* ---- ADX (ADCX/ADOX): BoringSSL bigint on Broadwell+ binaries ----------- */
struct emu_adx_out emu_adx(u64 a, u64 b, int width, int kind, int cf, int of)
{
	u64 mask = width == 8 ? ~0ULL : 0xffffffffULL;
	u64 sa = a & mask, sb = b & mask;
	unsigned __int128 wide;
	u64 res, sign = 1ULL << (width * 8 - 1);
	struct emu_adx_out out;

	wide = (unsigned __int128)sa + sb + (u64)(kind ? of : cf);
	res = (u64)wide & mask;
	out.result = res;
	if (kind == 0) {
		out.cf = (int)(wide >> (width * 8));
		out.of = of;			/* ADOX's flag, untouched by ADCX */
	} else {
		s64 x = (s64)(sa << (64 - width * 8)) >> (64 - width * 8);
		s64 y = (s64)(sb << (64 - width * 8)) >> (64 - width * 8);
		s64 z = (s64)(res << (64 - width * 8)) >> (64 - width * 8);

		out.cf = cf;			/* ADCX's flag, untouched by ADOX */
		out.of = ((x ^ z) & (y ^ z) & (s64)sign) != 0;
	}
	return out;
}
