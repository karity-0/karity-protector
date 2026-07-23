#include "obfuscate.h"

#include "karity/isa.h"

namespace karity {

namespace {

void emit_junk_ops(BytecodeEmitter &out, std::mt19937_64 &rng, int count)
{
    static const karity_vop kOps[] = {VOP_ADD, VOP_SUB, VOP_XOR, VOP_AND, VOP_OR};
    std::uniform_int_distribution<int> op_dist(0, 4);
    std::uniform_int_distribution<uint64_t> imm_dist(0, UINT64_MAX);

    for (int i = 0; i < count; i++) {
        out.push_imm(imm_dist(rng));
        out.push_imm(imm_dist(rng));
        out.op(kOps[op_dist(rng)]);
        out.drop(); // discard the junk result -- vstack depth unchanged, vregs untouched
    }
}

// Builds a condition on top of the vstack that is always nonzero (true),
// regardless of `carrier`'s actual value -- one of a few equivalent
// invariants, picked at random so the bytecode shape varies between builds.
void emit_always_true_predicate(BytecodeEmitter &out, uint8_t carrier, std::mt19937_64 &rng)
{
    std::uniform_int_distribution<int> variant_dist(0, 1);
    out.push_vreg(carrier);
    if (variant_dist(rng) == 0) {
        // (carrier | 1) & 1 == 1: ORing in bit 0 guarantees it, ANDing
        // with 1 isolates it -- always 1 no matter what carrier holds.
        out.push_imm(1);
        out.op(VOP_OR);
        out.push_imm(1);
        out.op(VOP_AND);
    } else {
        // (carrier & 1) | 1 == 1: same invariant, different-looking chain.
        out.push_imm(1);
        out.op(VOP_AND);
        out.push_imm(1);
        out.op(VOP_OR);
    }
}

} // namespace

void insert_obfuscation(BytecodeEmitter &out, uint8_t carrier_vreg, std::mt19937_64 &rng)
{
    std::uniform_int_distribution<int> junk_count_dist(1, 3);

    // Plain junk: always executes, provably has no effect.
    emit_junk_ops(out, rng, junk_count_dist(rng));

    // Opaque predicate guarding a second, structurally-dead junk block: a
    // static analyzer sees a data-dependent branch and has to do the
    // invariant math to learn it's not actually a decision point at all.
    emit_always_true_predicate(out, carrier_vreg, rng);
    size_t jcc_operand = out.emit_jcc_nz_placeholder(); // always taken
    emit_junk_ops(out, rng, junk_count_dist(rng));       // never reached
    out.patch_rel_to_here(jcc_operand);
}

} // namespace karity
