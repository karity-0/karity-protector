#pragma once

#include <cstdint>
#include <random>

#include "emitter.h"

namespace karity {

// Emits VMProtect/Themida-style filler between real lifted instructions:
//   - plain junk: a stack-neutral, vreg-neutral computation (push, arithmetic,
//     drop) that always executes but has no effect on the program's state.
//   - an opaque predicate: a branch built from `carrier_vreg` whose condition
//     is a mathematical invariant (e.g. (x|1)&1 == 1) that always evaluates
//     the same way regardless of the carrier's actual runtime value, guarding
//     a second junk block that is provably (but not *obviously*) dead code.
//
// `carrier_vreg` should be a register the surrounding real code just touched,
// so the predicate looks like it's inspecting live, meaningful state.
void insert_obfuscation(BytecodeEmitter &out, uint8_t carrier_vreg, std::mt19937_64 &rng);

} // namespace karity
