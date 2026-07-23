#pragma once

#include <cstdint>
#include <vector>

namespace karity {

// Describes one injected function that needs a synthesized x64 SEH
// RUNTIME_FUNCTION/UNWIND_INFO entry -- see runtime/vm_thunk.S's
// "SEH/exception interaction" header paragraph for the full picture of why
// this is needed at all (short version: table-based x64 SEH can't unwind
// through injected code with no Exception Directory entry, and the "no
// entry found" fallback Windows uses instead -- assume a true leaf function,
// rsp unchanged since entry -- is wrong for all three functions this
// project injects, since all three move rsp around).
//
// Every one of the three real uses (karity_vm_thunk, karity_vm_native_call,
// the generated interpreter) fits the exact same shape: some nonvolatile
// registers pushed in a fixed order (possibly none), then one `mov freereg,
// rsp` establishing a frame pointer that's never touched again until right
// before the function returns. That's expressive enough to recover the
// function's true entry rsp (and hence its own caller's return address)
// regardless of how rsp fluctuates *after* the frame pointer is set --
// which is the only part of each function's body an outbound call/unwind
// can actually be "inside of" -- without needing to model every individual
// push/sub/realign along the way. See build_exception_directory below.
struct SehFunction {
    uint32_t rva = 0;   // function's first byte, RVA
    uint32_t size = 0;  // function length in bytes (RUNTIME_FUNCTION.EndAddress = rva + size)

    // Nonvolatile registers (x64 numbering: RAX=0, RCX=1, RDX=2, RBX=3,
    // RSP=4, RBP=5, RSI=6, RDI=7, R8=8..R15=15) pushed with a plain 1-byte-
    // opcode `push reg` (or 2 bytes for R8-R15, REX.B), in push order,
    // *before* the frame pointer is established. Empty for karity_vm_thunk
    // and the generated interpreter (both set the frame pointer as their
    // very first action); {RBX, RBP, RSI, RDI} for karity_vm_native_call
    // (see runtime/vm_call.S).
    std::vector<int> pushed_before_fpreg;

    // Offset (from `rva`) of the first byte *after* the `mov frame_register,
    // rsp` instruction that establishes the frame pointer. Everything from
    // `rva` up to this offset is a narrow, deliberately-accepted gap (see the
    // header comment in runtime/vm_thunk.S): a fault in there would still
    // unwind incorrectly, but it's register-shuffling code with no realistic
    // fault source.
    uint32_t fpreg_offset = 0;

    // A *fixed*-size stack allocation (a plain `sub rsp, N`, N known at
    // protect time) occurring between `fpreg_offset` and the function's
    // first outbound call, if any -- 0 if there is none. Empirically (see
    // src/native/seh_unwind.cpp's build_unwind_info and the investigation
    // that led here, runtime/vm_thunk.S's header), a fixed adjustment in this
    // specific position needs its own UWOP_ALLOC_LARGE/SMALL code even
    // though FrameRegister is already set -- unlike *dynamic* adjustments
    // after it (a data-dependent realignment, or an outright rsp swap to an
    // unrelated value), which are safe to leave completely undescribed.
    // Nonzero only for karity_vm_thunk (its `sub rsp, 4096` outbound-call
    // headroom); karity_vm_native_call's absolute rsp swap and the generated
    // interpreter's transient, deep-in-the-dispatch-loop `sub rsp,40`/`add
    // rsp,40` bracket around its own outbound call both need no such code.
    uint32_t fixed_alloc_after_fpreg = 0;

    // UNWIND_INFO.SizeOfProlog -- fpreg_offset if fixed_alloc_after_fpreg is
    // 0, otherwise the offset right after the `sub rsp, fixed_alloc_after_
    // fpreg` instruction that follows it.
    uint32_t prolog_size = 0;

    // The register (same numbering as above) holding the established frame
    // pointer -- RBP for karity_vm_thunk and the generated interpreter, RBX
    // for karity_vm_native_call (see each file's own header comment for why
    // that particular register was free to repurpose).
    int frame_register = 0;
};

// Builds a self-contained blob to be placed at `blob_rva`: a RUNTIME_FUNCTION
// table (this image's existing Exception Directory contents, `original_table`
// -- raw bytes, already sorted, copied verbatim -- followed by one new entry
// per `functions`, all of which are guaranteed to have a higher RVA than
// every original entry since they live in a section appended after every
// original one) immediately followed by one UNWIND_INFO per new function.
// The returned blob's *first* `original_table.size() +
// functions.size() * 12` bytes are the complete, ready-to-use RUNTIME_FUNCTION
// table -- point IMAGE_DIRECTORY_ENTRY_EXCEPTION at `blob_rva` with that
// length as its Size.
//
// `blob_rva` has to be threaded in rather than left for the caller to add
// afterwards: each new RUNTIME_FUNCTION's UnwindInfoAddress field is an RVA
// pointing *into this same blob* (at the corresponding UNWIND_INFO), and that
// can only be expressed once the blob's own eventual placement is known --
// same reasoning as every other anchor-relative value already computed this
// way elsewhere in src/inject/injector.cpp.
std::vector<uint8_t> build_exception_directory(const std::vector<uint8_t> &original_table,
                                                const std::vector<SehFunction> &functions,
                                                uint32_t blob_rva);

} // namespace karity
