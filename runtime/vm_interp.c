/*
 * runtime/vm_interp.c -- the bytecode interpreter core.
 *
 * This file is compiled twice:
 *   - freestanding, into the injected runtime blob (runtime/CMakeLists.txt)
 *   - hosted, into a normal test binary (tests/) for correctness checking
 *
 * Deliberately dispatches via an if/else chain rather than a switch: a
 * switch over a dense opcode range tempts the compiler into a jump table
 * in .rodata, and this file must stay valid raw shellcode with no data
 * relocations once objcopy'd out of its container. If/else compiles to
 * plain relative branches, which are always position-independent.
 *
 * No libc calls (freestanding). Unaligned little-endian reads are done
 * manually rather than via memcpy, since -ffreestanding gives no guarantee
 * that a builtin memcpy call resolves to anything at link time.
 */
#include "vm_interp.h"

#include "karity/bytecode_crypt.h"

/* Native call passthrough, implemented in runtime/vm_call.S: swaps to the
 * real vreg[RSP], loads vreg[RCX/RDX/R8/R9] into the matching Win64 arg
 * registers, executes `call target_va`, and writes the result back into
 * vreg[RAX]. See that file for why this needs hand-written asm rather than
 * a plain C call. */
extern void karity_vm_native_call(karity_vmctx *ctx, uint64_t target_va);

static uint64_t karity_read_u64le(const uint8_t *p)
{
    uint64_t v;
    int i;

    v = 0;
    for (i = 0; i < 8; i++) {
        v |= ((uint64_t)p[i]) << (8 * i);
    }
    return v;
}

/* "Opcode rolling decryption" (include/karity/bytecode_crypt.h, look/todo.md
 * section C): the real, non-decoy opcode/operand bytes below are encrypted
 * at rest, keyed by this invocation's bytecode_base/bytecode_key_seed (see
 * isa.h) -- these two mirror karity_read_u64le above but decrypt through the
 * keystream first. `ip` may be at any position (these don't assume any
 * particular call order relative to other reads), so the offset is always
 * recomputed fresh from `ip - base`. The decoy/junk branches further down
 * (op == 0x05 etc.) are deliberately left reading raw memory -- see their
 * own comment below. */
static uint8_t karity_read_u8_enc(const uint8_t *ip, const uint8_t *base, uint64_t seed)
{
    uint64_t off = (uint64_t)(ip - base);
    return (uint8_t)(*ip ^ karity_bytecode_keystream_byte(seed, off));
}

static uint64_t karity_read_u64le_enc(const uint8_t *ip, const uint8_t *base, uint64_t seed)
{
    uint64_t off = (uint64_t)(ip - base);
    uint64_t v = 0;
    int i;

    for (i = 0; i < 8; i++) {
        uint8_t b = (uint8_t)(ip[i] ^ karity_bytecode_keystream_byte(seed, off + i));
        v |= ((uint64_t)b) << (8 * i);
    }
    return v;
}

/* PF = parity of the *low byte* of the result only (native x86 semantics),
 * not the whole 64-bit value. */
static uint64_t karity_parity(uint64_t result)
{
    uint8_t b = (uint8_t)result;
    b = (uint8_t)(b ^ (b >> 4));
    b = (uint8_t)(b ^ (b >> 2));
    b = (uint8_t)(b ^ (b >> 1));
    return (b & 1) ? 0 : KARITY_FLAG_PF;
}

static uint64_t karity_flags_add(uint64_t a, uint64_t b, uint64_t result)
{
    uint64_t f = karity_parity(result);
    if (result == 0) f |= KARITY_FLAG_ZF;
    if ((int64_t)result < 0) f |= KARITY_FLAG_SF;
    if (result < a) f |= KARITY_FLAG_CF;
    if (((~(a ^ b)) & (a ^ result)) >> 63) f |= KARITY_FLAG_OF;
    return f;
}

static uint64_t karity_flags_sub(uint64_t a, uint64_t b, uint64_t result)
{
    uint64_t f = karity_parity(result);
    if (result == 0) f |= KARITY_FLAG_ZF;
    if ((int64_t)result < 0) f |= KARITY_FLAG_SF;
    if (a < b) f |= KARITY_FLAG_CF;
    if (((a ^ b) & (a ^ result)) >> 63) f |= KARITY_FLAG_OF;
    return f;
}

/* AND/OR/XOR/TEST all clear CF and OF on real x86; only ZF/SF/PF depend on
 * the result. */
static uint64_t karity_flags_logic(uint64_t result)
{
    uint64_t f = karity_parity(result);
    if (result == 0) f |= KARITY_FLAG_ZF;
    if ((int64_t)result < 0) f |= KARITY_FLAG_SF;
    return f;
}

/* SF/ZF/PF from a shift's result -- shared by SHL/SHR/SAR (CF/OF differ per
 * operation and are computed by each caller separately; see isa.h). */
static uint64_t karity_flags_shift_szp(uint64_t result)
{
    uint64_t f = karity_parity(result);
    if (result == 0) f |= KARITY_FLAG_ZF;
    if ((int64_t)result < 0) f |= KARITY_FLAG_SF;
    return f;
}

/* Unsigned 128-bit (hi:lo) / 64-bit divisor -> 64-bit quotient + remainder,
 * via plain shift/subtract long division -- deliberately not
 * `((unsigned __int128)hi << 64 | lo) / divisor`, which would pull in
 * libgcc's __udivti3 for a division this wide (unlike a 64x64->128
 * multiply, which GCC lowers straight onto the hardware `mul`, there's no
 * equivalent single-instruction path from portable C to a 128/64 divide).
 * Matches this file's existing no-memcpy-either freestanding discipline
 * (see the top-of-file comment). Undefined input (divisor == 0, or a
 * quotient that doesn't fit in 64 bits) is the caller's problem to avoid --
 * see VOP_DIV/VOP_IDIV in isa.h; this loop just produces *some* value for
 * it rather than crashing. */
static void karity_udiv128(uint64_t hi, uint64_t lo, uint64_t divisor, uint64_t *quot, uint64_t *rem)
{
    uint64_t q = 0, r = 0;
    int i;

    for (i = 127; i >= 0; i--) {
        uint64_t bit = (i >= 64) ? ((hi >> (i - 64)) & 1u) : ((lo >> i) & 1u);
        r = (r << 1) | bit;
        q <<= 1;
        if (r >= divisor) {
            r -= divisor;
            q |= 1;
        }
    }
    *quot = q;
    *rem = r;
}

/* vstack overflow guard (see runtime/vm_thunk.S's header and isa.h's
 * vstack_limit comment): call right after `sp` has been decremented for a
 * push, before the value is actually written through it. Traps immediately
 * (rather than writing outside the vstack buffer, or letting the caller
 * silently resume native execution mid-block) -- see the identical guard in
 * the real injected interpreter, src/native/interp_codegen.cpp, for the
 * fuller rationale. __builtin_trap() lowers to a bare `ud2`, keeping this
 * file's no-libc-call discipline (see the top-of-file comment) rather than
 * reaching for abort(). A caller that leaves ctx->vstack_limit
 * zero-initialized (every existing hosted test that doesn't set it) gets
 * the pre-guard behavior back: no real `sp` is ever numerically below
 * address 0, so the check simply never fires. */
static void karity_check_vstack_overflow(const uint8_t *sp, const karity_vmctx *ctx)
{
    if ((uint64_t)(uintptr_t)sp < ctx->vstack_limit) {
        __builtin_trap();
    }
}

/* Evaluates a KARITY_CC_* condition against a vflags word. Written as an
 * if/else chain rather than a switch for the same reason as the dispatch
 * loop above: this file is objcopy'd into freestanding shellcode with no
 * data relocations, and a switch here risks the same jump-table temptation. */
static int karity_eval_cc(uint8_t cc, uint64_t flags)
{
    int cf = (flags & KARITY_FLAG_CF) != 0;
    int pf = (flags & KARITY_FLAG_PF) != 0;
    int zf = (flags & KARITY_FLAG_ZF) != 0;
    int sf = (flags & KARITY_FLAG_SF) != 0;
    int of = (flags & KARITY_FLAG_OF) != 0;

    if (cc == KARITY_CC_O)       return of;
    if (cc == KARITY_CC_NO)      return !of;
    if (cc == KARITY_CC_B)       return cf;
    if (cc == KARITY_CC_AE)      return !cf;
    if (cc == KARITY_CC_E)       return zf;
    if (cc == KARITY_CC_NE)      return !zf;
    if (cc == KARITY_CC_BE)      return cf || zf;
    if (cc == KARITY_CC_A)       return !cf && !zf;
    if (cc == KARITY_CC_S)       return sf;
    if (cc == KARITY_CC_NS)      return !sf;
    if (cc == KARITY_CC_P)       return pf;
    if (cc == KARITY_CC_NP)      return !pf;
    if (cc == KARITY_CC_L)       return sf != of;
    if (cc == KARITY_CC_GE)      return sf == of;
    if (cc == KARITY_CC_LE)      return zf || (sf != of);
    /* KARITY_CC_G */             return !zf && (sf == of);
}

/*
 * The handful of `else if (op == 0x..)` branches below whose sentinel value
 * doesn't match any karity_vop in isa.h are deliberate filler: op is a byte
 * read straight from memory, so the compiler can't prove these are
 * unreachable and won't fold them away, even though the lifter/emitter
 * never emits those byte values into real bytecode. They're written to
 * read plausibly (operand-shaped accesses into ip/sp/ctx) without writing
 * anything back, so they're harmless by construction regardless. The point
 * is purely to make the compiled dispatcher's real comparison chain harder
 * to pick out from the noise.
 */

void karity_vm_run(karity_vmctx *ctx)
{
    const uint8_t *ip;
    uint8_t *sp;
    const uint8_t *bc_base;
    uint64_t bc_seed;
    /* Execution-local scalar-float bookkeeping slots (see isa.h's comment
     * above VOP_PUSH_XREG) -- not part of karity_vmctx, not saved/restored
     * across VM entry/exit, scoped to this one karity_vm_run call only. */
    uint64_t xmm[KARITY_XREG_COUNT];

    ip = (const uint8_t *)(uintptr_t)ctx->vip;
    sp = (uint8_t *)(uintptr_t)ctx->vsp;
    bc_base = (const uint8_t *)(uintptr_t)ctx->bytecode_base;
    bc_seed = ctx->bytecode_key_seed;

    for (;;) {
        uint8_t op = karity_read_u8_enc(ip, bc_base, bc_seed);
        ip++;

        if (op == VOP_NOP) {
            /* nothing */
        } else if (op == 0x05) {
            uint64_t junk = karity_read_u64le(ip) ^ 0xA5A5A5A5A5A5A5A5ULL;
            (void)junk;
        } else if (op == VOP_VMEXIT) {
            break;
        } else if (op == 0x08) {
            uint8_t junk_idx = ip[0];
            (void)ctx->vreg[junk_idx & 0x0F];
        } else if (op == VOP_PUSH_IMM) {
            uint64_t imm = karity_read_u64le_enc(ip, bc_base, bc_seed);
            ip += 8;
            sp -= 8;
            karity_check_vstack_overflow(sp, ctx);
            *(uint64_t *)sp = imm;
        } else if (op == 0x0A) {
            uint64_t junk = *(const uint64_t *)sp + karity_read_u64le(ip);
            (void)junk;
        } else if (op == 0x0F) {
            uint64_t junk = ctx->rflags ^ ctx->vreg[ip[0] & 0x0F];
            (void)junk;
        } else if (op == VOP_PUSH_VREG) {
            uint8_t idx = karity_read_u8_enc(ip, bc_base, bc_seed);
            ip++;
            sp -= 8;
            karity_check_vstack_overflow(sp, ctx);
            *(uint64_t *)sp = ctx->vreg[idx];
        } else if (op == VOP_POP_VREG) {
            uint8_t idx = karity_read_u8_enc(ip, bc_base, bc_seed);
            ip++;
            ctx->vreg[idx] = *(uint64_t *)sp;
            sp += 8;
        } else if (op == 0x15) {
            uint64_t junk = *(const uint64_t *)sp;
            junk = (junk << 13) ^ (junk >> 7);
            (void)junk;
        } else if (op == VOP_PUSH_REL) {
            uint64_t delta = karity_read_u64le_enc(ip, bc_base, bc_seed);
            ip += 8;
            sp -= 8;
            karity_check_vstack_overflow(sp, ctx);
            *(uint64_t *)sp = ctx->anchor + delta;
        } else if (op == 0x1A) {
            uint64_t junk = ctx->anchor + karity_read_u64le(ip);
            (void)junk;
        } else if (op == VOP_DROP) {
            sp += 8;
        } else if (op == 0x1F) {
            uint64_t junk = ctx->vreg[ip[0] & 0x0F] + ctx->vreg[(ip[0] >> 4) & 0x0F];
            (void)junk;
        } else if (op == VOP_ADD) {
            uint64_t b = *(uint64_t *)sp; sp += 8;
            uint64_t a = *(uint64_t *)sp; sp += 8;
            uint64_t result = a + b;
            sp -= 8;
            *(uint64_t *)sp = result;
            ctx->vflags = karity_flags_add(a, b, result);
        } else if (op == VOP_SUB) {
            uint64_t b = *(uint64_t *)sp; sp += 8;
            uint64_t a = *(uint64_t *)sp; sp += 8;
            uint64_t result = a - b;
            sp -= 8;
            *(uint64_t *)sp = result;
            ctx->vflags = karity_flags_sub(a, b, result);
        } else if (op == VOP_XOR) {
            uint64_t b = *(uint64_t *)sp; sp += 8;
            uint64_t a = *(uint64_t *)sp; sp += 8;
            uint64_t result = a ^ b;
            sp -= 8;
            *(uint64_t *)sp = result;
            ctx->vflags = karity_flags_logic(result);
        } else if (op == VOP_AND) {
            uint64_t b = *(uint64_t *)sp; sp += 8;
            uint64_t a = *(uint64_t *)sp; sp += 8;
            uint64_t result = a & b;
            sp -= 8;
            *(uint64_t *)sp = result;
            ctx->vflags = karity_flags_logic(result);
        } else if (op == VOP_OR) {
            uint64_t b = *(uint64_t *)sp; sp += 8;
            uint64_t a = *(uint64_t *)sp; sp += 8;
            uint64_t result = a | b;
            sp -= 8;
            *(uint64_t *)sp = result;
            ctx->vflags = karity_flags_logic(result);
        } else if (op == VOP_CMP) {
            uint64_t b = *(uint64_t *)sp; sp += 8;
            uint64_t a = *(uint64_t *)sp; sp += 8;
            ctx->vflags = karity_flags_sub(a, b, a - b);
        } else if (op == VOP_TEST) {
            uint64_t b = *(uint64_t *)sp; sp += 8;
            uint64_t a = *(uint64_t *)sp; sp += 8;
            ctx->vflags = karity_flags_logic(a & b);
        } else if (op == VOP_NEG) {
            uint64_t a = *(uint64_t *)sp;
            uint64_t result = (uint64_t)(-(int64_t)a);
            *(uint64_t *)sp = result;
            ctx->vflags = karity_flags_sub(0, a, result);
        } else if (op == VOP_NOT) {
            *(uint64_t *)sp = ~*(uint64_t *)sp; /* native NOT never touches flags */
        } else if (op == VOP_INC) {
            uint64_t a = *(uint64_t *)sp;
            uint64_t result = a + 1;
            *(uint64_t *)sp = result;
            /* OF/SF/ZF/PF exactly like a native `a+1`; CF is untouched, unlike ADD */
            ctx->vflags = (karity_flags_add(a, 1, result) & ~(uint64_t)KARITY_FLAG_CF) |
                          (ctx->vflags & KARITY_FLAG_CF);
        } else if (op == VOP_DEC) {
            uint64_t a = *(uint64_t *)sp;
            uint64_t result = a - 1;
            *(uint64_t *)sp = result;
            ctx->vflags = (karity_flags_sub(a, 1, result) & ~(uint64_t)KARITY_FLAG_CF) |
                          (ctx->vflags & KARITY_FLAG_CF);
        } else if (op == VOP_SHL) {
            uint64_t count_raw = *(uint64_t *)sp; sp += 8;
            uint64_t a = *(uint64_t *)sp;
            uint8_t count = (uint8_t)(count_raw & 63);
            if (count != 0) {
                uint64_t result = a << count;
                uint64_t cf = (a >> (64 - count)) & 1;
                uint64_t f = karity_flags_shift_szp(result);
                if (cf) f |= KARITY_FLAG_CF;
                if (count == 1 && (((result >> 63) & 1) ^ cf)) f |= KARITY_FLAG_OF;
                *(uint64_t *)sp = result;
                ctx->vflags = f;
            }
        } else if (op == VOP_SHR) {
            uint64_t count_raw = *(uint64_t *)sp; sp += 8;
            uint64_t a = *(uint64_t *)sp;
            uint8_t count = (uint8_t)(count_raw & 63);
            if (count != 0) {
                uint64_t result = a >> count;
                uint64_t cf = (a >> (count - 1)) & 1;
                uint64_t f = karity_flags_shift_szp(result);
                if (cf) f |= KARITY_FLAG_CF;
                if (count == 1 && ((a >> 63) & 1)) f |= KARITY_FLAG_OF; /* OF = original MSB */
                *(uint64_t *)sp = result;
                ctx->vflags = f;
            }
        } else if (op == VOP_SAR) {
            uint64_t count_raw = *(uint64_t *)sp; sp += 8;
            int64_t a_signed = *(int64_t *)sp;
            uint64_t a = *(uint64_t *)sp;
            uint8_t count = (uint8_t)(count_raw & 63);
            if (count != 0) {
                /* arithmetic right shift: implementation-defined by the C
                   standard for negative signed values, but this project
                   only ever builds with GCC for x86-64, which -- like
                   every mainstream compiler -- defines it as sign-
                   extending, matching native SAR exactly. */
                uint64_t result = (uint64_t)(a_signed >> count);
                uint64_t cf = (a >> (count - 1)) & 1;
                uint64_t f = karity_flags_shift_szp(result);
                if (cf) f |= KARITY_FLAG_CF;
                /* OF is always 0 for SAR count==1 (sign can't change) -- nothing to set */
                *(uint64_t *)sp = result;
                ctx->vflags = f;
            }
        } else if (op == VOP_ROL) {
            uint64_t count_raw = *(uint64_t *)sp; sp += 8;
            uint64_t a = *(uint64_t *)sp;
            uint8_t count = (uint8_t)(count_raw & 63);
            if (count != 0) {
                uint64_t result = (a << count) | (a >> (64 - count));
                uint64_t cf = result & 1;
                uint64_t f = ctx->vflags; /* ROL/ROR never touch SF/ZF/PF */
                f = (f & ~(uint64_t)(KARITY_FLAG_CF | KARITY_FLAG_OF));
                if (cf) f |= KARITY_FLAG_CF;
                if (count == 1 && (((result >> 63) & 1) ^ cf)) f |= KARITY_FLAG_OF;
                *(uint64_t *)sp = result;
                ctx->vflags = f;
            }
        } else if (op == VOP_ROR) {
            uint64_t count_raw = *(uint64_t *)sp; sp += 8;
            uint64_t a = *(uint64_t *)sp;
            uint8_t count = (uint8_t)(count_raw & 63);
            if (count != 0) {
                uint64_t result = (a >> count) | (a << (64 - count));
                uint64_t cf = (result >> 63) & 1;
                uint64_t f = ctx->vflags; /* ROL/ROR never touch SF/ZF/PF */
                f = (f & ~(uint64_t)(KARITY_FLAG_CF | KARITY_FLAG_OF));
                if (cf) f |= KARITY_FLAG_CF;
                if (count == 1 && (((result >> 63) & 1) ^ ((result >> 62) & 1))) f |= KARITY_FLAG_OF;
                *(uint64_t *)sp = result;
                ctx->vflags = f;
            }
        } else if (op == VOP_MUL) {
            uint64_t b = *(uint64_t *)sp; sp += 8;
            uint64_t a = ctx->vreg[0]; /* RAX */
            unsigned __int128 product = (unsigned __int128)a * (unsigned __int128)b;
            uint64_t hi = (uint64_t)(product >> 64);
            ctx->vreg[0] = (uint64_t)product;
            ctx->vreg[2] = hi; /* RDX */
            ctx->vflags = (ctx->vflags & ~(uint64_t)(KARITY_FLAG_CF | KARITY_FLAG_OF)) |
                          (hi != 0 ? (KARITY_FLAG_CF | KARITY_FLAG_OF) : 0);
        } else if (op == VOP_IMUL1) {
            uint64_t b = *(uint64_t *)sp; sp += 8;
            int64_t a = (int64_t)ctx->vreg[0]; /* RAX */
            __int128 product = (__int128)a * (__int128)(int64_t)b;
            uint64_t lo = (uint64_t)product;
            uint64_t hi = (uint64_t)((unsigned __int128)product >> 64);
            uint64_t sign_ext = ((int64_t)lo < 0) ? UINT64_MAX : 0;
            ctx->vreg[0] = lo;
            ctx->vreg[2] = hi; /* RDX */
            ctx->vflags = (ctx->vflags & ~(uint64_t)(KARITY_FLAG_CF | KARITY_FLAG_OF)) |
                          (hi != sign_ext ? (KARITY_FLAG_CF | KARITY_FLAG_OF) : 0);
        } else if (op == VOP_IMUL2) {
            uint64_t b = *(uint64_t *)sp; sp += 8;
            uint64_t a = *(uint64_t *)sp;
            __int128 product = (__int128)(int64_t)a * (__int128)(int64_t)b;
            uint64_t lo = (uint64_t)product;
            uint64_t hi = (uint64_t)((unsigned __int128)product >> 64);
            uint64_t sign_ext = ((int64_t)lo < 0) ? UINT64_MAX : 0;
            *(uint64_t *)sp = lo;
            ctx->vflags = (ctx->vflags & ~(uint64_t)(KARITY_FLAG_CF | KARITY_FLAG_OF)) |
                          (hi != sign_ext ? (KARITY_FLAG_CF | KARITY_FLAG_OF) : 0);
        } else if (op == VOP_DIV) {
            uint64_t b = *(uint64_t *)sp; sp += 8; /* divisor */
            uint64_t hi = ctx->vreg[2]; /* RDX */
            uint64_t lo = ctx->vreg[0]; /* RAX */
            uint64_t q, r;
            karity_udiv128(hi, lo, b, &q, &r);
            ctx->vreg[0] = q;
            ctx->vreg[2] = r;
        } else if (op == VOP_IDIV) {
            int64_t b = (int64_t)(*(uint64_t *)sp); sp += 8; /* divisor */
            uint64_t hi = ctx->vreg[2]; /* RDX */
            uint64_t lo = ctx->vreg[0]; /* RAX */
            int neg_dividend = (int64_t)hi < 0;
            int neg_divisor = b < 0;
            uint64_t uhi = hi, ulo = lo;
            uint64_t udivisor;
            uint64_t uq, ur;
            if (neg_dividend) {
                ulo = ~ulo; uhi = ~uhi;
                ulo += 1;
                if (ulo == 0) uhi += 1;
            }
            /* (uint64_t)(-(b+1))+1 negates without signed overflow UB when b == INT64_MIN */
            udivisor = neg_divisor ? (uint64_t)(-(b + 1)) + 1 : (uint64_t)b;
            karity_udiv128(uhi, ulo, udivisor, &uq, &ur);
            ctx->vreg[0] = (neg_dividend != neg_divisor) ? (~uq + 1) : uq; /* quotient */
            ctx->vreg[2] = neg_dividend ? (~ur + 1) : ur; /* remainder, sign of dividend */
        } else if (op == 0x28) {
            uint64_t junk = (*(const uint64_t *)sp * 2654435761u) ^ ctx->vip;
            (void)junk;
        } else if (op == 0x2C) {
            uint64_t junk = ~ctx->vreg[ip[0] & 0x0F];
            (void)junk;
        } else if (op == VOP_LOAD8) {
            uint64_t addr = *(uint64_t *)sp;
            *(uint64_t *)sp = *(const uint8_t *)(uintptr_t)addr;
        } else if (op == VOP_LOAD16) {
            uint64_t addr = *(uint64_t *)sp;
            *(uint64_t *)sp = *(const uint16_t *)(uintptr_t)addr;
        } else if (op == VOP_LOAD32) {
            uint64_t addr = *(uint64_t *)sp;
            *(uint64_t *)sp = *(const uint32_t *)(uintptr_t)addr;
        } else if (op == VOP_LOAD64) {
            uint64_t addr = *(uint64_t *)sp;
            *(uint64_t *)sp = *(const uint64_t *)(uintptr_t)addr;
        } else if (op == 0x39) {
            uint64_t junk = *(const uint64_t *)sp;
            junk = (junk >> 3) | (junk << 61);
            (void)junk;
        } else if (op == 0x3B) {
            uint64_t junk = ctx->vsp ^ karity_read_u64le(ip);
            (void)junk;
        } else if (op == VOP_STORE8) {
            uint64_t value = *(uint64_t *)sp; sp += 8;
            uint64_t addr  = *(uint64_t *)sp; sp += 8;
            *(uint8_t *)(uintptr_t)addr = (uint8_t)value;
        } else if (op == VOP_STORE16) {
            uint64_t value = *(uint64_t *)sp; sp += 8;
            uint64_t addr  = *(uint64_t *)sp; sp += 8;
            *(uint16_t *)(uintptr_t)addr = (uint16_t)value;
        } else if (op == VOP_STORE32) {
            uint64_t value = *(uint64_t *)sp; sp += 8;
            uint64_t addr  = *(uint64_t *)sp; sp += 8;
            *(uint32_t *)(uintptr_t)addr = (uint32_t)value;
        } else if (op == VOP_STORE64) {
            uint64_t value = *(uint64_t *)sp; sp += 8;
            uint64_t addr  = *(uint64_t *)sp; sp += 8;
            *(uint64_t *)(uintptr_t)addr = value;
        } else if (op == 0x3E) {
            uint64_t junk = ctx->vreg[ip[0] & 0x0F] - ctx->exit_target;
            (void)junk;
        } else if (op == VOP_CALL) {
            uint64_t delta = karity_read_u64le_enc(ip, bc_base, bc_seed);
            ip += 8;
            /* flush our locals into ctx before handing off: the native
             * callee (or something it calls) may itself be virtualized
             * and re-enter through vm_thunk, which reads/writes ctx->vreg
             * directly and has no idea about ip/sp living in registers here */
            ctx->vip = (uint64_t)(uintptr_t)ip;
            ctx->vsp = (uint64_t)(uintptr_t)sp;
            karity_vm_native_call(ctx, ctx->anchor + delta);
            /* native_call doesn't touch vip/vsp; ip/sp locals are still valid */
        } else if (op == 0x44) {
            uint64_t junk = ctx->anchor ^ (uint64_t)(uintptr_t)ip;
            (void)junk;
        } else if (op == VOP_CALL_IND) {
            uint64_t target = *(uint64_t *)sp; sp += 8;
            /* same flush-before-native-call rationale as VOP_CALL */
            ctx->vip = (uint64_t)(uintptr_t)ip;
            ctx->vsp = (uint64_t)(uintptr_t)sp;
            karity_vm_native_call(ctx, target);
        } else if (op == VOP_JMP) {
            int64_t rel = (int64_t)karity_read_u64le_enc(ip, bc_base, bc_seed);
            ip += 8;
            ip += rel;
        } else if (op == 0x47) {
            uint64_t junk = *(const uint64_t *)sp + (uint64_t)(uintptr_t)sp;
            (void)junk;
        } else if (op == VOP_JCC_NZ) {
            uint64_t cond = *(uint64_t *)sp; sp += 8;
            int64_t rel = (int64_t)karity_read_u64le_enc(ip, bc_base, bc_seed);
            ip += 8;
            if (cond != 0) {
                ip += rel;
            }
        } else if (op == 0x4B) {
            uint64_t junk = ctx->rflags + ctx->vreg[ip[0] & 0x0F];
            (void)junk;
        } else if (op == VOP_JCC) {
            uint8_t cc = karity_read_u8_enc(ip, bc_base, bc_seed);
            ip++;
            int64_t rel = (int64_t)karity_read_u64le_enc(ip, bc_base, bc_seed);
            ip += 8;
            if (karity_eval_cc(cc, ctx->vflags)) {
                ip += rel;
            }
        } else if (op == VOP_VMEXIT_REL) {
            uint64_t delta = karity_read_u64le_enc(ip, bc_base, bc_seed);
            ip += 8;
            ctx->exit_target = ctx->anchor + delta;
            break;
        } else if (op == VOP_MOVZX) {
            uint8_t src_size = karity_read_u8_enc(ip, bc_base, bc_seed);
            ip++;
            uint64_t a = *(uint64_t *)sp;
            uint64_t mask = (src_size == 1) ? 0xFFu : 0xFFFFu;
            *(uint64_t *)sp = a & mask; /* never touches vflags, matches native MOVZX */
        } else if (op == VOP_MOVSX) {
            uint8_t src_size = karity_read_u8_enc(ip, bc_base, bc_seed);
            ip++;
            uint8_t dst_size = karity_read_u8_enc(ip, bc_base, bc_seed);
            ip++;
            uint64_t a = *(uint64_t *)sp;
            uint64_t result;
            if (src_size == 1) result = (uint64_t)(int64_t)(int8_t)a;
            else if (src_size == 2) result = (uint64_t)(int64_t)(int16_t)a;
            else result = (uint64_t)(int64_t)(int32_t)a;
            if (dst_size == 4) result &= 0xFFFFFFFFu; /* see isa.h: NOT the same as a direct 64-bit sign extend */
            *(uint64_t *)sp = result; /* never touches vflags, matches native MOVSX/MOVSXD */
        } else if (op == VOP_PUSH_XREG) {
            uint8_t idx = karity_read_u8_enc(ip, bc_base, bc_seed);
            ip++;
            sp -= 8;
            karity_check_vstack_overflow(sp, ctx);
            *(uint64_t *)sp = xmm[idx];
        } else if (op == VOP_POP_XREG) {
            uint8_t idx = karity_read_u8_enc(ip, bc_base, bc_seed);
            ip++;
            xmm[idx] = *(uint64_t *)sp;
            sp += 8;
        } else if (op == VOP_ADDSD) {
            double b = *(double *)sp; sp += 8;
            double a = *(double *)sp; sp += 8;
            double result = a + b;
            sp -= 8;
            *(double *)sp = result;
        } else if (op == VOP_SUBSD) {
            double b = *(double *)sp; sp += 8;
            double a = *(double *)sp; sp += 8;
            double result = a - b;
            sp -= 8;
            *(double *)sp = result;
        } else if (op == VOP_MULSD) {
            double b = *(double *)sp; sp += 8;
            double a = *(double *)sp; sp += 8;
            double result = a * b;
            sp -= 8;
            *(double *)sp = result;
        } else if (op == VOP_DIVSD) {
            double b = *(double *)sp; sp += 8;
            double a = *(double *)sp; sp += 8;
            double result = a / b;
            sp -= 8;
            *(double *)sp = result;
        } else if (op == VOP_ADDSS) {
            float b = *(float *)sp; sp += 8;
            float a = *(float *)sp; sp += 8;
            float result = a + b;
            sp -= 8;
            *(uint64_t *)sp = 0; /* zero the full slot: see isa.h, upper 4 bytes are always zero for an SS value */
            *(float *)sp = result;
        } else if (op == VOP_SUBSS) {
            float b = *(float *)sp; sp += 8;
            float a = *(float *)sp; sp += 8;
            float result = a - b;
            sp -= 8;
            *(uint64_t *)sp = 0;
            *(float *)sp = result;
        } else if (op == VOP_MULSS) {
            float b = *(float *)sp; sp += 8;
            float a = *(float *)sp; sp += 8;
            float result = a * b;
            sp -= 8;
            *(uint64_t *)sp = 0;
            *(float *)sp = result;
        } else if (op == VOP_DIVSS) {
            float b = *(float *)sp; sp += 8;
            float a = *(float *)sp; sp += 8;
            float result = a / b;
            sp -= 8;
            *(uint64_t *)sp = 0;
            *(float *)sp = result;
        } else if (op == VOP_CVTSI2SD) {
            int64_t a = *(int64_t *)sp;
            double result = (double)a;
            *(double *)sp = result;
        } else if (op == VOP_CVTTSD2SI) {
            double a = *(double *)sp;
            int64_t result = (int64_t)a; /* undefined for out-of-range/NaN input -- see isa.h */
            *(int64_t *)sp = result;
        } else if (op == VOP_CVTSI2SS) {
            int64_t a = *(int64_t *)sp;
            float result = (float)a;
            *(uint64_t *)sp = 0;
            *(float *)sp = result;
        } else if (op == VOP_CVTTSS2SI) {
            float a = *(float *)sp;
            int64_t result = (int64_t)a; /* undefined for out-of-range/NaN input -- see isa.h */
            *(int64_t *)sp = result;
        } else {
            /* unknown opcode: fail closed rather than run off into garbage */
            break;
        }
    }

    ctx->vip = (uint64_t)(uintptr_t)ip;
    ctx->vsp = (uint64_t)(uintptr_t)sp;
}
