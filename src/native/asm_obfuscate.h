#pragma once

#include <random>
#include <string>

namespace karity {

// Rewrites an AT&T-syntax assembly source (as produced by `gcc -S`) by
// splicing self-contained no-op junk -- emitted as `.byte` runs from
// x86_junk.cpp's generators (emit_native_junk / emit_native_opaque_predicate /
// emit_junk_call / emit_overlap_* / emit_indirect_jump / emit_antistepover_call /
// emit_stack_noise) -- between instructions inside executable
// (.text) sections only. The assembler then re-computes every displacement and
// the linker/nm re-derive every symbol offset, which is why this source-level
// rewrite is sound where a byte-level splice into the already-linked blob would
// not be (that would shift every internal rel32 and every offset the injector
// depends on).
//
// Every junk blob is a strict register/flag/stack no-op that is fully balanced
// at the instruction boundary it's inserted at (see x86_junk.h), so it is safe
// to drop between any two instructions of -O2 output -- even across a flag
// producer/consumer pair (cmp;jcc), since the flag-touching generators bracket
// themselves with pushfq/popfq. Junk is only ever placed inside .text, never in
// .rodata/.data (where "instructions" are really data and must stay verbatim).
//
// `density` is roughly the probability of inserting a junk blob after each
// eligible instruction (clamped to [0,1]).
std::string obfuscate_asm(const std::string &att_asm, std::mt19937_64 &rng, double density = 0.5);

} // namespace karity
