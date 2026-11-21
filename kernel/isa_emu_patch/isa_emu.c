// SPDX-License-Identifier: GPL-2.0
/*
 * Userspace emulation of x86 instructions that Skylake-family CPUs lack
 * (GFNI, AVX-VNNI(-INT8), SHA-NI, 256-bit VAES/VPCLMULQDQ, AVX-IFMA).
 * Entered from the #UD handler for user-mode faults. AVX-512 and AMX are not handled.
 */
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/atomic.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/spinlock.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <asm/ptrace.h>
#include <asm/traps.h>
#include <asm/fpu/api.h>
#include <asm/fpu/types.h>
#include <asm/fpu/xstate.h>
#include "isa_emu_core.h"
#include "isa_emu.h"

static bool isa_emu_enabled __ro_after_init = true;

static int __init isa_emu_setup(char *s)
{
	isa_emu_enabled = false;
	return 1;
}
__setup("noisaemu", isa_emu_setup);

static int __init isa_emu_boot_init(void)
{
	isa_emu_core_init();
	return 0;
}
early_initcall(isa_emu_boot_init);

enum op_kind {
	K_NONE, K_GF2P8MUL, K_GF2P8AFF, K_GF2P8AFFINV, K_VNNI_BUSD, K_VNNI_WSSD, K_VNNI8,
	K_IFMA_L, K_IFMA_H, K_VAES, K_CLMUL, K_ZEROUPPER,
	K_SHA1NEXTE, K_SHA1MSG1, K_SHA1MSG2, K_SHA256RNDS2, K_SHA256MSG1, K_SHA256MSG2, K_SHA1RNDS4,
};

struct op {
	enum op_kind kind;
	bool vex, has_imm, three_op;
	bool is_avx, store, shift_var;
	int len;            /* 16 or 32 */
	int dst, src1, rm;  /* vector register numbers; rm < 0 means memory */
	int sat, a_signed, b_signed, aes_op;
	int velem, vaux, memsz, dst_gpr;
	enum emu_vop vop;
	void __user *mem_addr;
	u8 imm;
};

/* ---- GPR helpers for BMI1/2, LZCNT/TZCNT and MOVBE ---------------------- */
static u64 gpr_read(struct pt_regs *regs, int n)
{
	switch (n) {
	case 0: return regs->ax;
	case 1: return regs->cx;
	case 2: return regs->dx;
	case 3: return regs->bx;
	case 4: return regs->sp;
	case 5: return regs->bp;
	case 6: return regs->si;
	case 7: return regs->di;
	case 8: return regs->r8;
	case 9: return regs->r9;
	case 10: return regs->r10;
	case 11: return regs->r11;
	case 12: return regs->r12;
	case 13: return regs->r13;
	case 14: return regs->r14;
	case 15: return regs->r15;
	}
	return 0;
}

static void gpr_write(struct pt_regs *regs, int n, u64 v)
{
	switch (n) {
	case 0: regs->ax = v; break;
	case 1: regs->cx = v; break;
	case 2: regs->dx = v; break;
	case 3: regs->bx = v; break;
	case 4: regs->sp = v; break;
	case 5: regs->bp = v; break;
	case 6: regs->si = v; break;
	case 7: regs->di = v; break;
	case 8: regs->r8 = v; break;
	case 9: regs->r9 = v; break;
	case 10: regs->r10 = v; break;
	case 11: regs->r11 = v; break;
	case 12: regs->r12 = v; break;
	case 13: regs->r13 = v; break;
	case 14: regs->r14 = v; break;
	case 15: regs->r15 = v; break;
	}
}

/* Haswell-baseline scalar instructions a Sandy/Ivy Bridge CPU lacks. */
enum gpr_kind {
	G_ANDN, G_BEXTR, G_BLSI, G_BLSMSK, G_BLSR, G_BZHI, G_RORX,
	G_LZCNT, G_TZCNT, G_MOVBE, G_ADCX, G_ADOX,
};
struct gop {
	enum gpr_kind kind;
	int dst, src1, src2;	/* GPR numbers; src2 < 0 = immediate in imm */
	int width;		/* 4 or 8 */
	bool is_imm, vex, store, mem_src;
	u8 imm;
	void __user *mem_addr;
};

/* Classify a VEX-encoded AVX/AVX2 instruction. Called before the newer-extension
 * table; returns false for instructions we do not emulate (they get SIGILL). */
static bool classify_avx(struct insn *insn, struct op *o, u8 opc, int m, int pp,
			 int w, int l, int vv, int reg, int rm)
{
	int sub = X86_MODRM_REG(insn->modrm.value);
	enum emu_vop vop;
	int elem = 4, aux = 0;

	(void)vv;
	/* vzeroupper/vzeroall: VEX.0F 77, no ModR/M byte. */
	if (m == 0 && opc == 0x77 && pp == 0) {
		o->kind = K_ZEROUPPER;
		return true;
	}

	vop = EMU_V_MOV;
	o->is_avx = true;
	o->len = l ? 32 : 16;
	o->memsz = o->len;

	if (m == 0) {			/* VEX.0F */
		switch (opc) {
		case 0x10: case 0x28: case 0x6f:
			vop = EMU_V_MOV; elem = o->len; break;
		case 0x11: case 0x29: case 0x7f:
			vop = EMU_V_MOV; elem = o->len; o->store = true; o->src1 = reg; break;
		case 0x57: case 0xef:
			vop = EMU_V_XOR; elem = o->len; break;
		case 0xeb: vop = EMU_V_OR; elem = o->len; break;
		case 0xdb: vop = pp == 3 ? EMU_V_ANDN : EMU_V_AND; elem = o->len; break;
		case 0xfe: vop = EMU_V_ADD; elem = 4; break;
		case 0xd4: vop = EMU_V_ADD; elem = 8; break;
		case 0xfd: vop = EMU_V_ADD; elem = 2; break;
		case 0xfc: vop = EMU_V_ADD; elem = 1; break;
		case 0xfb: vop = EMU_V_SUB; elem = 8; break;
		case 0xfa: vop = EMU_V_SUB; elem = 4; break;
		case 0xf9: vop = EMU_V_SUB; elem = 2; break;
		case 0xf8: vop = EMU_V_SUB; elem = 1; break;
		case 0x76: vop = EMU_V_EQ; elem = 4; break;
		case 0x75: vop = EMU_V_EQ; elem = 2; break;
		case 0x74: vop = EMU_V_EQ; elem = 1; break;
		case 0x64: vop = EMU_V_GT; elem = 4; break;	/* vpcmpgtd */
		case 0xd7: vop = EMU_V_MOVMSK; elem = 1; o->dst_gpr = reg; break;
		case 0x50: vop = EMU_V_MOVMSK; elem = pp == 1 ? 8 : 4; o->dst_gpr = reg; break;
		case 0x71: case 0x72: case 0x73: {
			int kind;

			elem = opc == 0x71 ? 2 : opc == 0x72 ? 4 : 8;
			if (X86_MODRM_MOD(insn->modrm.value) != 3)
				return false;
			if (sub == 6) { vop = EMU_V_SLL; kind = 0; }
			else if (sub == 2) { vop = EMU_V_SRL; kind = 1; }
			else if (sub == 4) { vop = EMU_V_SRA; kind = 2; }
			else return false;
			if (insn->immediate.nbytes)
				aux = insn->immediate.value & 0xff;
			else {
				o->shift_var = true;
				aux = kind;		/* vaux carries SLL/SRL/SRA for variable form */
				o->src1 = vv;		/* VEX.vvvv holds the shift counts */
			}
			o->dst = rm;			/* ModRM.rm is the source/destination */
			break;
		}
		case 0x14: vop = EMU_V_UNPCKL; elem = pp == 1 ? 8 : 4; break;
		case 0x15: vop = EMU_V_UNPCKH; elem = pp == 1 ? 8 : 4; break;
		case 0x5b: vop = EMU_V_CVTTPS2DQ; elem = 4; break;
		case 0x5a: vop = EMU_V_CVTPD2PS; elem = 4; break;
		default: return false;
		}
	} else if (m == 2) {		/* VEX.0F38 */
		switch (opc) {
		case 0x7a: vop = EMU_V_BROADCAST; elem = 1; aux = 1; o->memsz = 1; break;
		case 0x7b: vop = EMU_V_BROADCAST; elem = 2; aux = 2; o->memsz = 2; break;
		case 0x7c: vop = EMU_V_BROADCAST; elem = w ? 8 : 4; aux = elem; o->memsz = elem; break;
		case 0x16: vop = EMU_V_BROADCAST; elem = pp == 1 ? 8 : 4; aux = elem; o->memsz = elem; break;
		case 0x00: vop = EMU_V_SHUFB; elem = 1; break;
		case 0x45: case 0x46: case 0x47: {	/* vpsrlv*, vpsrav*, vpsllv* */
			int kind = opc == 0x45 ? 1 : opc == 0x46 ? 2 : 0;

			vop = EMU_V_SLL; elem = w ? 8 : 4;
			o->shift_var = true; aux = kind;
			break;
		}
		case 0x0c: vop = EMU_V_PERMILPS; elem = 4; aux = insn->immediate.nbytes ?
					(insn->immediate.value & 0xff) : -1; break;
		case 0x0d: vop = EMU_V_PERMILPD; elem = 8; aux = insn->immediate.nbytes ?
					(insn->immediate.value & 0xff) : -1; break;
		case 0x1c: vop = EMU_V_ABS; elem = 1; break;
		case 0x1d: vop = EMU_V_ABS; elem = 2; break;
		case 0x1e: vop = EMU_V_ABS; elem = 4; break;
		case 0x1f: vop = EMU_V_ABS; elem = 8; break;
		case 0x20: vop = EMU_V_MOVSX; elem = 2; aux = 1; break;
		case 0x21: vop = EMU_V_MOVSX; elem = 4; aux = 1; break;
		case 0x22: vop = EMU_V_MOVSX; elem = 8; aux = 1; break;
		case 0x23: vop = EMU_V_MOVSX; elem = 4; aux = 2; break;
		case 0x24: vop = EMU_V_MOVSX; elem = 8; aux = 2; break;
		case 0x25: vop = EMU_V_MOVSX; elem = 8; aux = 4; break;
		case 0x30: vop = EMU_V_MOVZX; elem = 2; aux = 1; break;
		case 0x31: vop = EMU_V_MOVZX; elem = 4; aux = 1; break;
		case 0x32: vop = EMU_V_MOVZX; elem = 8; aux = 1; break;
		case 0x33: vop = EMU_V_MOVZX; elem = 4; aux = 2; break;
		case 0x34: vop = EMU_V_MOVZX; elem = 8; aux = 2; break;
		case 0x35: vop = EMU_V_MOVZX; elem = 8; aux = 4; break;
		case 0x29: vop = EMU_V_EQ; elem = 8; break;
		case 0x37: vop = EMU_V_GT; elem = 8; break;
		case 0x38: vop = EMU_V_MIN_S; elem = 1; break;
		case 0x39: vop = EMU_V_MIN_S; elem = 4; break;
		case 0x3a: vop = EMU_V_MIN_U; elem = 2; break;
		case 0x3b: vop = EMU_V_MIN_U; elem = 4; break;
		case 0x3c: vop = EMU_V_MAX_S; elem = 1; break;
		case 0x3d: vop = EMU_V_MAX_S; elem = 4; break;
		case 0x3e: vop = EMU_V_MAX_U; elem = 2; break;
		case 0x3f: vop = EMU_V_MAX_U; elem = 4; break;
		case 0x40: vop = EMU_V_MUL; elem = 4; break;
		case 0x41: vop = EMU_V_MUL; elem = 8; break;
		case 0x90: vop = EMU_V_PERMQ; elem = 8; aux = insn->immediate.value & 0xff; break;
		case 0x91: vop = EMU_V_PERMQ; elem = 8; aux = insn->immediate.value & 0xff; break;
		case 0x92: vop = EMU_V_PERM2I128; elem = 16; aux = insn->immediate.value & 0xff; break;
		default: return false;
		}
	} else if (m == 3) {		/* VEX.0F3A */
		switch (opc) {
		case 0x02: vop = EMU_V_BLEND; elem = 4; aux = insn->immediate.value & 0xff; break;
		case 0x0d: vop = EMU_V_BLEND; elem = 8; aux = insn->immediate.value & 0xff; break;
		case 0x0e: vop = EMU_V_BLEND; elem = 2; aux = insn->immediate.value & 0xff; break;
		case 0x0f: vop = EMU_V_ALIGNR; elem = 1; aux = insn->immediate.value & 0xff; break;
		case 0x04: vop = EMU_V_PERMILPS; elem = 4; aux = insn->immediate.value & 0xff; break;
		case 0x05: vop = EMU_V_PERMILPD; elem = 8; aux = insn->immediate.value & 0xff; break;
		default: return false;
		}
	} else {
		return false;
	}

	o->vop = vop;
	o->velem = elem;
	o->vaux = aux;
	if (o->dst_gpr >= 0)
		o->is_avx = true;
	return true;
}

/* Classify a decoded instruction; returns false if not one we emulate. */
static bool classify(struct insn *insn, struct op *o)
{
	u8 modrm, opc, pp, m;
	int i, reg, rm, vv = 0, w = 0, l = 0;

	memset(o, 0, sizeof(*o));
	modrm = insn->modrm.value;
	reg = X86_MODRM_REG(modrm);
	rm = X86_MODRM_RM(modrm);

	if (insn->vex_prefix.nbytes) {
		u8 *vp = insn->vex_prefix.bytes;

		if (vp[0] != 0xc4 && vp[0] != 0xc5)
			return false;		/* EVEX/XOP */
		o->vex = true;
		m = insn_vex_m_bits(insn);
		pp = insn_vex_p_bits(insn);
		w = !!X86_VEX_W(vp[2]);
		l = !!X86_VEX_L(vp[2]);
		vv = (~X86_VEX_V(vp[2])) & 0xf;
		if (!X86_VEX_R(vp[1]))
			reg += 8;
		if (insn->vex_prefix.nbytes == 3 && !X86_VEX_B(vp[1]))
			rm += 8;
		if (insn->opcode.nbytes != 1)
			return false;
		opc = insn->opcode.bytes[0];
		if (classify_avx(insn, o, opc, m, pp, w, l, vv, reg, rm))
			return true;
	} else {
		/* legacy SSE encodings: 0F 38 xx / 0F 3A xx, with optional 66 */
		if (insn->opcode.nbytes != 3 || insn->opcode.bytes[0] != 0x0f)
			return false;
		m = insn->opcode.bytes[1] == 0x38 ? 2 : insn->opcode.bytes[1] == 0x3a ? 3 : 0;
		if (!m)
			return false;
		opc = insn->opcode.bytes[2];
		pp = 0;
		for (i = 0; i < insn->prefixes.nbytes; i++) {
			if (insn->prefixes.bytes[i] == 0x66)
				pp = 1;
			else if (insn->prefixes.bytes[i] == 0xf3)
				pp = 2;
			else if (insn->prefixes.bytes[i] == 0xf2)
				pp = 3;
		}
		if (insn->rex_prefix.nbytes) {
			if (X86_REX_R(insn->rex_prefix.value))
				reg += 8;
			if (X86_REX_B(insn->rex_prefix.value))
				rm += 8;
		}
		/* register-form r/m below; memory form is flagged by mod != 3 */
	}

	o->len = (o->vex && l) ? 32 : 16;
	o->dst = reg;
	o->src1 = o->vex ? vv : reg;
	o->rm = X86_MODRM_MOD(modrm) == 3 ? rm : -1;
	o->three_op = o->vex;

	if (m == 2) {
		if (o->vex) {
			if (pp == 1 && !w && opc == 0xcf) { o->kind = K_GF2P8MUL; return true; }
			if (pp == 1 && !w && opc >= 0x50 && opc <= 0x51) {
				o->kind = K_VNNI_BUSD; o->sat = opc & 1; return true;
			}
			if (pp == 1 && !w && opc >= 0x52 && opc <= 0x53) {
				o->kind = K_VNNI_WSSD; o->sat = opc & 1; return true;
			}
			if (!w && (opc == 0x50 || opc == 0x51) && pp != 1) {
				o->kind = K_VNNI8; o->sat = opc & 1;
				o->a_signed = pp == 3 || pp == 2;	/* F2: bssd, F3: bsud */
				o->b_signed = pp == 3;
				return true;
			}
			if (pp == 1 && w && (opc == 0xb4 || opc == 0xb5)) {
				o->kind = opc == 0xb4 ? K_IFMA_L : K_IFMA_H; return true;
			}
			if (pp == 1 && l && opc >= 0xdc && opc <= 0xdf) {
				o->kind = K_VAES; o->aes_op = opc - 0xdc; return true;
			}
			return false;
		}
		switch (opc) {
		case 0xc8: o->kind = K_SHA1NEXTE; break;
		case 0xc9: o->kind = K_SHA1MSG1; break;
		case 0xca: o->kind = K_SHA1MSG2; break;
		case 0xcb: o->kind = K_SHA256RNDS2; break;
		case 0xcc: o->kind = K_SHA256MSG1; break;
		case 0xcd: o->kind = K_SHA256MSG2; break;
		case 0xcf: if (pp != 1) return false; o->kind = K_GF2P8MUL; break;
		default: return false;
		}
		return true;
	}
	if (m == 3) {
		o->has_imm = true;
		o->imm = insn->immediate.value;
		if (o->vex) {
			if (pp == 1 && w && opc == 0xce) { o->kind = K_GF2P8AFF; return true; }
			if (pp == 1 && w && opc == 0xcf) { o->kind = K_GF2P8AFFINV; return true; }
			if (pp == 1 && l && opc == 0x44) { o->kind = K_CLMUL; return true; }
			return false;
		}
		if (opc == 0xcc && pp == 0) { o->kind = K_SHA1RNDS4; return true; }
		if (pp == 1 && opc == 0xce) { o->kind = K_GF2P8AFF; return true; }
		if (pp == 1 && opc == 0xcf) { o->kind = K_GF2P8AFFINV; return true; }
	}
	return false;
}

/* ---- register file access, on the saved xsave image ---- */

static void vreg_load(struct xregs_state *xs, int n, int len, u8 *out)
{
	if (xs->header.xfeatures & XFEATURE_MASK_SSE)
		memcpy(out, &xs->i387.xmm_space[4 * n], 16);
	else
		memset(out, 0, 16);
	if (len == 32) {
		u8 *hi = get_xsave_addr(xs, XFEATURE_YMM);

		if (hi)
			memcpy(out + 16, hi + 16 * n, 16);
		else
			memset(out + 16, 0, 16);
	}
}

static void vreg_store(struct xregs_state *xs, int n, int len, const u8 *in, bool vex)
{
	if (!(xs->header.xfeatures & XFEATURE_MASK_SSE)) {
		memset(xs->i387.xmm_space, 0, sizeof(xs->i387.xmm_space));
		xs->header.xfeatures |= XFEATURE_MASK_SSE;
	}
	memcpy(&xs->i387.xmm_space[4 * n], in, 16);
	if (vex) {		/* VEX writes zero-extend to the full register */
		u8 *hi = xstate_addr_for_write(xs, XFEATURE_YMM);

		if (hi) {
			if (len == 32)
				memcpy(hi + 16 * n, in + 16, 16);
			else
				memset(hi + 16 * n, 0, 16);
		}
	}
}

static void do_emulate(struct op *o, struct xregs_state *xs, const u8 *mem,
		       struct pt_regs *regs, u8 *out)
{
	u8 a[32], b[32], d[32];
	int len = o->len, i;

	if (o->kind == K_ZEROUPPER) {
		for (i = 0; i < 16; i++) {
			u8 *hi = xstate_addr_for_write(xs, XFEATURE_YMM);

			if (hi)
				memset(hi + 16 * i, 0, 16);
		}
		return;
	}

	if (o->store) {
		/* ModRM.reg holds the source vector; r/m is the memory destination. */
		vreg_load(xs, o->src1, len, b);
		memset(a, 0, len);
		memset(d, 0, len);
	} else {
		vreg_load(xs, o->src1, len, a);
		if (o->rm >= 0)
			vreg_load(xs, o->rm, len, b);
		else
			memcpy(b, mem, len);
		vreg_load(xs, o->dst, len, d);
	}

	if (o->is_avx && (o->velem <= 0 || o->len < o->velem || o->len < 16)) {
		/* A bad decode must SIGILL the process, not divide-by-zero the kernel. */
		pr_warn_ratelimited("isa_emu: BAD decode kind=%d vop=%d len=%d elem=%d aux=%d comm=%s\n",
				    o->kind, (int)o->vop, o->len, o->velem, o->vaux, current->comm);
		return;
	}
	if (o->is_avx) {
		if (o->shift_var)
			emu_vshift_var(d, a, b, len, o->velem, o->vaux);
		else
			emu_vop(d, a, b, len, o->velem, o->vop, o->vaux);
	} else
	switch (o->kind) {
	case K_GF2P8MUL:    emu_gf2p8mulb(d, a, b, len); break;
	case K_GF2P8AFF:    emu_gf2p8affineqb(d, a, b, o->imm, len); break;
	case K_GF2P8AFFINV: emu_gf2p8affineinvqb(d, a, b, o->imm, len); break;
	case K_VNNI_BUSD:   emu_vpdpbusd(d, a, b, len, o->sat); break;
	case K_VNNI_WSSD:   emu_vpdpwssd(d, a, b, len, o->sat); break;
	case K_VNNI8:       emu_vpdp8(d, a, b, len, o->sat, o->a_signed, o->b_signed); break;
	case K_IFMA_L:      emu_vpmadd52(d, a, b, len, 0); break;
	case K_IFMA_H:      emu_vpmadd52(d, a, b, len, 1); break;
	case K_VAES:        emu_vaes(d, a, b, len, o->aes_op); break;
	case K_CLMUL:       emu_vpclmulqdq(d, a, b, o->imm, len); break;
	case K_SHA1NEXTE:   emu_sha1nexte(d, b); break;
	case K_SHA1MSG1:    emu_sha1msg1(d, b); break;
	case K_SHA1MSG2:    emu_sha1msg2(d, b); break;
	case K_SHA1RNDS4:   emu_sha1rnds4(d, b, o->imm); break;
	case K_SHA256MSG1:  emu_sha256msg1(d, b); break;
	case K_SHA256MSG2:  emu_sha256msg2(d, b); break;
	case K_SHA256RNDS2: {
		u8 x0[16];

		vreg_load(xs, 0, 16, x0);
		emu_sha256rnds2(d, b, x0);
		break;
	}
	default: return;
	}

	if (out)
		memcpy(out, d, len);
	if (o->dst_gpr >= 0) {
		u32 m = (u32)d[0] | (u32)d[1] << 8 | (u32)d[2] << 16 | (u32)d[3] << 24;

		gpr_write(regs, o->dst_gpr, m);
	} else if (!o->store) {
		vreg_store(xs, o->dst, len, d, o->vex || o->is_avx);
	}
}


/* ---- profile: which (file, offset) traps most ---- */
#define PROF_SLOTS 16384
struct prof_ent {
	u64 key;		/* (ino << 24) ^ file offset, never 0 once used */
	u64 off;
	atomic64_t count;
	int kind;
	char path[112];
};
static struct prof_ent prof[PROF_SLOTS];
static DEFINE_SPINLOCK(prof_lock);

static void prof_hit(unsigned long ip, int kind)
{
	struct vm_area_struct *vma;
	struct file *f = NULL;
	u64 off = 0, key;
	char *tmp, *p = NULL;
	unsigned int h, i;

	mmap_read_lock(current->mm);
	vma = find_vma(current->mm, ip);
	if (vma && vma->vm_start <= ip) {
		f = vma->vm_file ? get_file(vma->vm_file) : NULL;
		off = ((u64)vma->vm_pgoff << PAGE_SHIFT) + (ip - vma->vm_start);
	}
	mmap_read_unlock(current->mm);
	key = f ? ((u64)file_inode(f)->i_ino << 28) ^ off ^ ((u64)file_inode(f)->i_sb->s_dev << 52) : (u64)ip | (1ULL << 63);
	key |= 1;
	h = (key * 0x9E3779B97F4A7C15ULL) >> 50;
	for (i = 0; i < PROF_SLOTS; i++) {
		struct prof_ent *e = &prof[(h + i) % PROF_SLOTS];

		if (READ_ONCE(e->key) == key) {
			atomic64_inc(&e->count);
			goto out;
		}
		if (!READ_ONCE(e->key)) {
			char name[sizeof(e->path)] = "";

			/* resolve the name outside the lock; d_path may sleep */
			tmp = kmalloc(PATH_MAX, GFP_KERNEL);
			if (f && tmp)
				p = d_path(&f->f_path, tmp, PATH_MAX);
			strscpy(name, IS_ERR_OR_NULL(p) ? (f ? "?" : current->comm) : p, sizeof(name));
			kfree(tmp);
			spin_lock(&prof_lock);
			if (!e->key) {
				memcpy(e->path, name, sizeof(name));
				e->off = off;
				e->kind = kind;
				atomic64_set(&e->count, 1);
				smp_wmb();
				WRITE_ONCE(e->key, key);
				spin_unlock(&prof_lock);
				goto out;
			}
			spin_unlock(&prof_lock);
			i--;	/* slot got taken meanwhile; recheck it */
		}
	}
out:
	if (f)
		fput(f);
}

static void prof_dump(void)
{
	int top[24], n = 0, i, j;

	for (i = 0; i < PROF_SLOTS; i++) {
		long c = READ_ONCE(prof[i].key) ? atomic64_read(&prof[i].count) : 0;

		if (!c)
			continue;
		for (j = n; j > 0 && atomic64_read(&prof[top[j - 1]].count) < c; j--)
			if (j < 24)
				top[j] = top[j - 1];
		if (j < 24) {
			top[j] = i;
			if (n < 24)
				n++;
		}
	}
	for (i = 0; i < n; i++)
		pr_info("isa_emu_prof: %9lld kind=%d off=%#llx %s\n", atomic64_read(&prof[top[i]].count),
			prof[top[i]].kind, prof[top[i]].off, prof[top[i]].path);
}

/* ---- Haswell-baseline GPR instructions (BMI1/2, LZCNT/TZCNT, MOVBE) ----- */
static bool classify_gpr(struct insn *insn, struct gop *g)
{
	int reg = X86_MODRM_REG(insn->modrm.value), rm = X86_MODRM_RM(insn->modrm.value);
	int sub = reg, m = 0, pp = 0, w = 0, vv = 0, opc, i;
	bool vex = insn->vex_prefix.nbytes > 0, f3 = false, f2 = false, p66 = false;

	memset(g, 0, sizeof(*g));
	g->vex = vex;
	g->width = 4;

	if (vex) {
		u8 *vp = insn->vex_prefix.bytes;

		if (vp[0] != 0xc4 && vp[0] != 0xc5)
			return false;
		if (insn->opcode.nbytes != 1)
			return false;
		m = insn_vex_m_bits(insn);
		pp = insn_vex_p_bits(insn);
		w = !!X86_VEX_W(vp[2]);
		vv = (~X86_VEX_V(vp[2])) & 0xf;
		if (!X86_VEX_R(vp[1]))
			reg += 8;
		if (insn->vex_prefix.nbytes == 3 && !X86_VEX_B(vp[1]))
			rm += 8;
		opc = insn->opcode.bytes[0];
		g->width = w ? 8 : 4;
		g->dst = reg;
		g->src1 = vv;
		g->src2 = rm;
		g->is_imm = insn->immediate.nbytes > 0;
		g->imm = insn->immediate.value;
		g->mem_src = X86_MODRM_MOD(insn->modrm.value) != 3;

		if (pp || m == 1)
			return false;
		if (m == 2) {
			switch (opc) {
			case 0xf2: g->kind = G_ANDN; return true;
			case 0xf7: g->kind = G_BEXTR; return true;
			case 0xf3:
				g->kind = sub == 1 ? G_BLSI : sub == 2 ? G_BLSMSK :
					  sub == 3 ? G_BLSR : (enum gpr_kind)0;
				return g->kind != 0;
			case 0xf5: g->kind = G_BZHI; return true;
			}
		}
		if (m == 3 && opc == 0xf0) {
			g->kind = G_RORX; return true;
		}
		return false;
	}

	for (i = 0; i < insn->prefixes.nbytes; i++) {
		if (insn->prefixes.bytes[i] == 0xf3)
			f3 = true;
		else if (insn->prefixes.bytes[i] == 0xf2)
			f2 = true;
		else if (insn->prefixes.bytes[i] == 0x66)
			p66 = true;
	}
	if (insn->rex_prefix.nbytes) {
		if (X86_REX_R(insn->rex_prefix.value))
			reg += 8;
		if (X86_REX_B(insn->rex_prefix.value))
			rm += 8;
		if (X86_REX_W(insn->rex_prefix.value))
			g->width = 8;
	}
	g->dst = reg;
	g->src2 = rm;
	g->mem_src = X86_MODRM_MOD(insn->modrm.value) != 3;

	if (insn->opcode.nbytes == 2 && insn->opcode.bytes[0] == 0x0f && f3) {
		opc = insn->opcode.bytes[1];
		if (opc == 0xbd) { g->kind = G_LZCNT; return true; }
		if (opc == 0xbc) { g->kind = G_TZCNT; return true; }
	}
	if (insn->opcode.nbytes == 3 && insn->opcode.bytes[0] == 0x0f &&
	    insn->opcode.bytes[1] == 0x38) {
		opc = insn->opcode.bytes[2];
		if (opc == 0xf0 || opc == 0xf1) {
			g->kind = G_MOVBE;
			g->store = opc == 0xf1;
			return true;
		}
		/* ADCX: 66 0F 38 F6 /r ; ADOX: F3 0F 38 F6 /r (ADX, Broadwell+) */
		if (opc == 0xf6 && !f2) {
			if (p66) { g->kind = G_ADCX; return true; }
			if (f3)  { g->kind = G_ADOX; return true; }
		}
	}
	return false;
}

static u64 gpr_ld(const u8 *p, int n)
{
	u64 v = 0;
	int i;

	for (i = 0; i < n; i++)
		v |= (u64)p[i] << (8 * i);
	return v;
}

static void do_gpr(struct gop *g, struct pt_regs *regs, const u8 *mem, void __user *addr)
{
	u64 a, b = 0, r;
	u32 ctrl = 0;
	enum emu_grop op;

	switch (g->kind) {
	case G_ANDN:   op = EMU_G_ANDN;   b = gpr_read(regs, g->src1); break;
	case G_BEXTR:  op = EMU_G_BEXTR;  ctrl = g->is_imm ? g->imm :
					(u32)gpr_read(regs, g->src1); break;
	case G_BLSI:   op = EMU_G_BLSI;   break;
	case G_BLSMSK: op = EMU_G_BLSMSK; break;
	case G_BLSR:   op = EMU_G_BLSR;   break;
	case G_BZHI:   op = EMU_G_BZHI;   ctrl = g->imm; break;
	case G_RORX:   op = EMU_G_RORX;   ctrl = g->imm; break;
	case G_LZCNT:  op = EMU_G_LZCNT;  break;
	case G_TZCNT:  op = EMU_G_TZCNT;  break;
	case G_MOVBE:  op = EMU_G_MOVBE;  break;
	case G_ADCX: case G_ADOX: op = EMU_G_ANDN; break; /* handled below */
	default: return;
	}

	/* MOVBE store: ModRM.reg is the source register, r/m the memory destination. */
	if (g->store)
		a = gpr_read(regs, g->dst);
	else if (g->mem_src)
		a = gpr_ld(mem, g->width);
	else
		a = gpr_read(regs, g->src2);

	/* ADCX/ADOX: DEST = DEST + r/m + CF (or OF); only that flag is written. */
	if (g->kind == G_ADCX || g->kind == G_ADOX) {
		u64 dest = gpr_read(regs, g->dst);
		int cf = !!(regs->flags & (1UL << 0));	/* X86_EFLAGS_CF */
		int of = !!(regs->flags & (1UL << 11));	/* X86_EFLAGS_OF */
		struct emu_adx_out out = emu_adx(dest, a, g->width,
						 g->kind == G_ADCX ? 0 : 1, cf, of);

		gpr_write(regs, g->dst, out.result);
		if (g->kind == G_ADCX)
			regs->flags = (regs->flags & ~(1UL << 0)) | (out.cf ? (1UL << 0) : 0);
		else
			regs->flags = (regs->flags & ~(1UL << 11)) | (out.of ? (1UL << 11) : 0);
		return;
	}

	r = emu_grop(op, a, b, ctrl, g->width);
	if (g->store) {
		if (copy_to_user(addr, &r, g->width))
			force_sig_fault(SIGSEGV, SEGV_MAPERR, addr);
	} else {
		gpr_write(regs, g->dst, r);
	}
}

bool isa_emu_handle_ud(struct pt_regs *regs)
{
	unsigned char buf[MAX_INSN_SIZE];
	struct insn insn;
	struct op o;
	struct gop g;
	u8 mem[32], out[32];
	struct xregs_state *xs;
	void __user *addr = NULL;
	bool is_gpr;
	int nbuf;

	if (!isa_emu_enabled || !user_mode(regs) || !boot_cpu_has(X86_FEATURE_XSAVE))
		return false;
	nbuf = insn_fetch_from_user(regs, buf);
	if (nbuf <= 0 || !insn_decode_from_regs(&insn, regs, buf, nbuf))
		return false;
	if (classify(&insn, &o))
		is_gpr = false;
	else if (classify_gpr(&insn, &g))
		is_gpr = true;
	else
		return false;

	/* The decoder does not fold VEX.X/B into the REX bits it uses for addressing. */
	if (insn.vex_prefix.nbytes && (is_gpr ? g.mem_src : o.rm < 0)) {
		u8 *vp = insn.vex_prefix.bytes;
		u8 rex = 0x40;

		if (insn.vex_prefix.nbytes == 3) {
			if (!X86_VEX_X(vp[1]))
				rex |= 2;
			if (!X86_VEX_B(vp[1]))
				rex |= 1;
		}
		insn.rex_prefix.value = rex;
		insn.rex_prefix.nbytes = 1;
	}

	if (is_gpr) {
		if (g.mem_src || g.store) {
			addr = insn_get_addr_ref(&insn, regs);
			if (addr == (void __user *)-1L)
				return false;
			if (g.mem_src && copy_from_user(mem, addr, g.width)) {
				force_sig_fault(SIGSEGV, SEGV_MAPERR, addr);
				return true;
			}
		}
		do_gpr(&g, regs, mem, addr);
	} else {
		if (o.rm < 0) {
			addr = insn_get_addr_ref(&insn, regs);
			if (addr == (void __user *)-1L)
				return false;
			o.mem_addr = addr;
			if (!o.store) {
				memset(mem, 0, sizeof(mem));
				if (copy_from_user(mem, addr, o.memsz)) {
					force_sig_fault(SIGSEGV, SEGV_MAPERR, addr);
					return true;
				}
			}
		}
		if (o.is_avx && (o.velem <= 0 || o.len < o.velem || o.len < 16)) {
			pr_warn_ratelimited("isa_emu: BAD decode vop=%d len=%d elem=%d aux=%d comm=%s\n",
					    (int)o.vop, o.len, o.velem, o.vaux, current->comm);
			return false;	/* let the normal #UD path SIGILL this process */
		}
		xs = fpu_emu_begin();
		do_emulate(&o, xs, mem, regs, out);
		fpu_emu_end();
		if (o.store && copy_to_user(o.mem_addr, out, o.memsz))
			force_sig_fault(SIGSEGV, SEGV_MAPERR, o.mem_addr);
	}

	regs->ip += insn.length;
	{
		static atomic64_t total;
		long n = atomic64_inc_return(&total);
		int kind = is_gpr ? 100 + (int)g.kind : o.kind;

		prof_hit(regs->ip - insn.length, kind);
		if (!(n & 0xfffff)) {
			pr_info("isa_emu: %ld instructions emulated (last: %s[%d] kind=%d)\n",
				n, current->comm, task_pid_nr(current), kind);
			prof_dump();
		}
	}
	return true;
}
