/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Software implementations of x86 instructions that Skylake-family CPUs
 * (e.g. Whiskey Lake i5-8365U) lack: GFNI, AVX-VNNI, SHA-NI, 256-bit VAES and
 * VPCLMULQDQ, and AVX-IFMA.
 *
 * Pure functions on byte vectors, with no kernel dependencies, so the same
 * file builds into the kernel and into a userspace test harness.
 * Vectors are little-endian byte arrays; `len` is 16 (xmm) or 32 (ymm).
 */
#ifndef ISA_EMU_CORE_H
#define ISA_EMU_CORE_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
#endif

/* GFNI. `x` is the data source, `m` the matrix (or second multiplicand) source. */
void emu_gf2p8affineqb(u8 *dst, const u8 *x, const u8 *m, u8 imm, int len);
void emu_gf2p8affineinvqb(u8 *dst, const u8 *x, const u8 *m, u8 imm, int len);
void emu_gf2p8mulb(u8 *dst, const u8 *a, const u8 *b, int len);

/* AVX-VNNI. `acc` is the destination/accumulator, `a` = first source (vvvv), `b` = second. */
void emu_vpdpbusd(u8 *acc, const u8 *a, const u8 *b, int len, int saturate);
void emu_vpdpwssd(u8 *acc, const u8 *a, const u8 *b, int len, int saturate);

/* AVX-VNNI-INT8: dword += sum of four byte products. a_signed/b_signed pick the byte signedness. */
void emu_vpdp8(u8 *acc, const u8 *a, const u8 *b, int len, int saturate, int a_signed, int b_signed);

/* AVX-IFMA: acc.qword += low/high 52 bits of the 104-bit product of the low 52 bits of a and b. */
void emu_vpmadd52(u8 *acc, const u8 *a, const u8 *b, int len, int high);

/* VAES: one AES round per 128-bit lane. `state` is the data, `rk` the round key. */
enum { EMU_AESENC, EMU_AESENCLAST, EMU_AESDEC, EMU_AESDECLAST };
void emu_vaes(u8 *dst, const u8 *state, const u8 *rk, int len, int op);

/* VPCLMULQDQ: per 128-bit lane; imm bit 0 picks a's qword, bit 4 picks b's qword. */
void emu_vpclmulqdq(u8 *dst, const u8 *a, const u8 *b, u8 imm, int len);

/* Builds the AES tables; call once before emu_vaes(). */
void isa_emu_core_init(void);

/* ---- AVX/AVX2 baseline (pre-Haswell Intel: Sandy/Ivy Bridge) ------------
 * Scalar emulation of the VEX-encoded integer operations that bionic, the
 * dynamic linker and the C++ runtime use on the Haswell x86-64 baseline.
 * Vectors are little-endian byte arrays, `len` is 16 (xmm) or 32 (ymm).
 */
enum emu_vop {
	EMU_V_MOV, EMU_V_AND, EMU_V_OR, EMU_V_XOR, EMU_V_ANDN,
	EMU_V_ADD, EMU_V_SUB, EMU_V_ADDS_S, EMU_V_ADDS_U, EMU_V_SUBS_S, EMU_V_SUBS_U,
	EMU_V_EQ, EMU_V_GT, EMU_V_MIN_S, EMU_V_MAX_S, EMU_V_MIN_U, EMU_V_MAX_U,
	EMU_V_SLL, EMU_V_SRL, EMU_V_SRA,
	EMU_V_SHUFB, EMU_V_ALIGNR, EMU_V_UNPCKL, EMU_V_UNPCKH, EMU_V_PACKUS,
	EMU_V_MUL, EMU_V_MULHI, EMU_V_MULADD, EMU_V_SAD, EMU_V_ABS, EMU_V_SIGN,
	EMU_V_PERMQ, EMU_V_PERM2I128, EMU_V_PERMILPS, EMU_V_PERMILPD,
	EMU_V_BLEND, EMU_V_BROADCAST, EMU_V_MOVSX, EMU_V_MOVZX, EMU_V_MOVMSK,
	EMU_V_CVTTPS2DQ, EMU_V_CVTPS2DQ, EMU_V_CVTPD2PS,
};
/* a = destination/first source, b = second source, len = 16/32,
 * elem = element width in bytes, aux = immediate (shift count / imm8 / src size). */
void emu_vop(u8 *dst, const u8 *a, const u8 *b, int len, int elem, enum emu_vop op, int aux);
/* Variable-count shifts: b holds the per-element counts. kind: 0=SLL, 1=SRL, 2=SRA. */
void emu_vshift_var(u8 *dst, const u8 *a, const u8 *b, int len, int elem, int kind);
/* Sign bits of the elements of a (one bit per element, 32-bit little-endian result in dst). */
void emu_vmovmsk(u8 *dst, const u8 *a, int len, int elem);

/* SHA-NI. All operate on 128-bit values; `dst` is also the first source. */
void emu_sha1rnds4(u8 *dst, const u8 *src, u8 imm);
void emu_sha1nexte(u8 *dst, const u8 *src);
void emu_sha1msg1(u8 *dst, const u8 *src);
void emu_sha1msg2(u8 *dst, const u8 *src);
void emu_sha256rnds2(u8 *dst, const u8 *src, const u8 *xmm0);
void emu_sha256msg1(u8 *dst, const u8 *src);
void emu_sha256msg2(u8 *dst, const u8 *src);

#endif
