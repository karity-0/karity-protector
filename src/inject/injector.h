#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "native/runtime_rewrite.h" // RuntimeBlobLayout
#include "pe/pe_image.h"

namespace karity {

// Virtualizes the image's OEP plus, optionally, any number of additional
// function entry points (`extra_entry_rvas`) in the same pass: each site is
// lifted to its own independent karity bytecode blob and gets its own
// `call thunk` + {bytecode_va, exit_target} parameter pair (see
// runtime/vm_thunk.S for the ABI) overwriting its first few bytes, exactly
// like the OEP patch always has. All sites share one appended section (one
// runtime blob copy, one generated interpreter -- both are already
// stateless/reentrant and carry no notion of "which site" invoked them) but
// each keeps its own anchor, so their bytecode's anchor-relative addressing
// (VOP_PUSH_REL/CALL/VMEXIT_REL) stays independent per site.
//
// Extra entry points must be explicit RVAs the caller already knows point
// at liftable function entries -- this does no function discovery of its
// own. Throws if any site has nothing liftable, if two sites are the same
// RVA, if two sites' probe windows overlap (their bytes would collide),
// or if there's no header slack left for the new section.
//
// Every site is independently scanned for nanomite placement past its own
// lifted region, and all sites' resulting entries are merged into one
// shared site table (runtime/nanomite_veh.c looks a faulting RIP up with a
// flat linear scan, so it doesn't need to know which site an entry came
// from). Site 0 is OEP, unless `skip_oep` is set, in which case it's the
// first of `extra_entry_rvas` instead (see skip_oep below).
//
// `skip_oep`: don't virtualize OEP at all, only `extra_entry_rvas`. OEP is
// usually CRT startup code that branches into main() almost immediately --
// often so close that OEP's own probe window unavoidably overlaps main()'s,
// making it impossible to virtualize both (the overlap check above rejects
// that combination outright). Set this when OEP itself isn't worth
// protecting and would otherwise just block virtualizing the function that
// actually is.
//
// A VOP_CALL/VOP_CALL_IND that lands on *another* site's own vm_thunk entry
// (i.e. one virtualized site's bytecode calls straight into a second
// virtualized site, nesting one karity_vm_thunk invocation inside another)
// is safe: vm_thunk.S (see that file's header for the fuller history) gives
// each live nesting depth its own scratch slot (karity_vmctx + private
// vstack) in a small fixed-size array, so a nested invocation no longer
// overwrites the outer, still-suspended invocation's state. This used to be
// a real limitation -- both a static single-instance buffer (shared by
// every call regardless of nesting) and, before that, scratch carved out of
// the live stack (colliding via address arithmetic instead) both let a
// nested invocation stomp the outer one's vmctx/vstack -- but neither
// applies anymore. The one remaining bound: nesting deeper than
// KARITY_VM_MAX_DEPTH (vm_thunk.S) clamps to the last slot, so two
// invocations at or past that depth *do* collide again -- a known, bounded
// fallback (same spirit as the fixed 4 KiB vstack size), not a hard
// guarantee against arbitrarily deep nesting. A native (non-virtualized)
// call into a virtualized site was never affected either way -- there's no
// nesting, since it doesn't go through karity_vm_native_call's stack swap
// at all.
// `anti_analysis_categories` is a KARITY_ANTI_ANALYSIS_* bitmask (see
// include/karity/anti_debug.h) chosen from the --anti-debug/--anti-vm/
// --anti-sandbox CLI flags: it's baked into the OEP stub's anti-analysis
// install call so the running program only runs the detection categories the
// user opted into. 0 (no flags) leaves all anti-analysis detection off --
// see that header for the per-category false-positive reasoning.
//
// `anti_tamper` (--anti-tamper) turns on self-integrity checking: the
// generated interpreter is hashed at protect time and that checksum is folded
// into every site's bytecode decryption key, so any post-protection patch to
// the interpreter corrupts decryption instead of tripping a defeatable branch
// (see include/karity/integrity.h). It adds an integrity install call to the
// OEP stub and stores each key quad as (real_seed ^ H_expected). Off by
// default; unlike the anti-analysis categories it has no legitimate-use false
// positives (the image's own bytes are identical for every user), so it's a
// safe switch to leave on.
// `layout` supplies the runtime blob bytes and every symbol offset the injector
// patches/references -- either default_runtime_layout() (the static embedded
// blob) or build_obfuscated_runtime() (a freshly recompiled, junk-obfuscated
// one). See native/runtime_rewrite.h.
void inject_vm_at_entry(PeImage &img, const RuntimeBlobLayout &layout,
                        const std::vector<uint32_t> &extra_entry_rvas = {}, bool skip_oep = false,
                        uint32_t anti_analysis_categories = 0, bool anti_tamper = false);

} // namespace karity
