#pragma once

#include <cstdint>
#include <random>
#include <vector>

#include "karity/opcode_map.h"

namespace karity {

// Generates the VM interpreter -- dispatch loop plus every opcode handler
// from include/karity/isa.h -- as fresh x86-64 machine code, built directly
// with src/native/x64_asm.h rather than compiled once from C. Different
// every call: dispatch-comparison/handler-layout order is shuffled and
// native junk/opaque predicates (native/x86_junk.h) are interspersed both
// between dispatch comparisons and within each handler's own instruction
// sequence, so the real logic never sits as one clean, recognizable block.
//
// Win64 ABI: takes karity_vmctx* in RCX, matching the karity_vm_run(ctx)
// signature vm_thunk.S expects at the far end of karity_interp_ptr.
//
// The generated interpreter is a single, stateless, reentrant blob: it just
// runs from wherever ctx->vip/vsp point, with no notion of "which call site"
// invoked it -- so it's shared as-is across every virtualization site in the
// image (see src/inject/injector.cpp), each with its own, independent
// ctx->anchor.
//
// native_call_rel_to_interp is native_call_va - interp_va: both the
// precompiled karity_vm_native_call (see runtime/vm_call.S) and this
// generated interpreter live at fixed, site-independent offsets within the
// same shared runtime blob/section, so this delta is a protect-time constant
// that has nothing to do with any particular call site's anchor. The
// VOP_CALL/VOP_CALL_IND handlers resolve the live address by fetching their
// own current RIP (via the call-rel32-self/pop idiom, see x64_asm.h's
// call_rel32_self) and adding this delta -- deliberately *not*
// ctx->anchor + delta: ctx->anchor differs per call site, and this constant
// is baked once for the one shared interpreter, so it must not depend on
// which site happens to be live when a given VOP_CALL executes. (Every
// *other* anchor-relative value -- VOP_PUSH_REL, VOP_VMEXIT_REL, and the
// CALL/CALL_IND *target* delta -- lives in each site's own bytecode instead
// of being baked into the interpreter, so those stay correctly anchor-
// relative per invocation.)
//
// `opcode_map` picks the physical byte value the dispatch loop compares
// against for each opcode (default: identity, see opcode_map.h) -- pass the
// same map given to every site's try_lift() call so this interpreter and
// the bytecode it runs agree on what each byte means.
//
// `prolog_size_out`, if non-null, receives the byte length of this function's
// SEH prologue (the `push rbp`/`mov rbp,rsp` frame-pointer setup emitted
// first, see the prologue comment in interp_codegen.cpp) -- src/native/
// seh_unwind.cpp needs this to build a correct UNWIND_INFO.SizeOfProlog for
// the generated blob (see look/todo.md's SEH/exception-interaction entry and
// runtime/vm_thunk.S's header for the full picture).
std::vector<uint8_t> generate_interpreter(uint64_t native_call_rel_to_interp, std::mt19937_64 &rng,
                                           const OpcodeMap &opcode_map = OpcodeMap(),
                                           size_t *prolog_size_out = nullptr);

} // namespace karity
