#include "seh_unwind.h"

#include <algorithm>
#include <stdexcept>

namespace karity {

namespace {

constexpr int kUwopPushNonvol = 0;
constexpr int kUwopAllocLarge = 1;
constexpr int kUwopAllocSmall = 2;
constexpr int kUwopSetFpreg = 3;

void emit_u16le(std::vector<uint8_t> &out, uint16_t v)
{
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>(v >> 8));
}

void emit_u32le(std::vector<uint8_t> &out, uint32_t v)
{
    for (int i = 0; i < 4; i++) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

uint32_t align_up(uint32_t v, uint32_t a) { return (v + a - 1) / a * a; }

// One UNWIND_CODE slot: CodeOffset (byte 0), UnwindOp|OpInfo<<4 (byte 1) --
// see the UNWIND_CODE bitfield layout this mirrors (MSDN "x64 exception
// handling"). A push's own byte length depends on whether it needed a REX.B
// prefix (registers R8-R15), matching src/native/x64_asm.cpp's push_reg.
int push_insn_size(int reg) { return reg >= 8 ? 2 : 1; }

// Builds one function's UNWIND_INFO (Version=1, Flags=UNW_FLAG_NHANDLER=0 --
// none of these three functions has (or needs) a language-specific handler,
// since none of them ever catches anything itself; they just need to be
// *unwindable through*). Codes are stored in decreasing CodeOffset order,
// matching how RtlVirtualUnwind expects to walk them (reverse chronological:
// whatever happened *last* in the prologue is described *first*):
//   1. the fixed alloc after the frame pointer (fixed_alloc_after_fpreg), if any
//   2. the frame-pointer SET_FPREG itself
//   3. each earlier PUSH_NONVOL, in reverse push order
// See seh_unwind.h's SehFunction comment for why this shape covers all three
// real cases, and why (1) is empirically required for karity_vm_thunk
// specifically even though FrameRegister makes it look redundant.
std::vector<uint8_t> build_unwind_info(const SehFunction &fn)
{
    if (fn.prolog_size > 0xFF) throw std::runtime_error("karity: SEH prolog too long for UNWIND_INFO.SizeOfProlog");

    // Each "slot" is 2 bytes: {CodeOffset, UnwindOp|OpInfo<<4} for a normal
    // code, or raw data (e.g. ALLOC_LARGE's size operand) for an extra slot
    // that doesn't count toward CountOfCodes on its own.
    std::vector<uint8_t> slots; // built as a flat byte stream, 2 bytes/slot
    size_t real_slot_count = 0;

    auto emit_code = [&](uint32_t code_offset, int op, int op_info) {
        slots.push_back(static_cast<uint8_t>(code_offset));
        slots.push_back(static_cast<uint8_t>((op & 0xF) | ((op_info & 0xF) << 4)));
        real_slot_count++;
    };

    if (fn.fixed_alloc_after_fpreg != 0) {
        const uint32_t size = fn.fixed_alloc_after_fpreg;
        if (size % 8 != 0) throw std::runtime_error("karity: SEH fixed_alloc_after_fpreg must be a multiple of 8");
        if (size >= 8 && size <= 128) {
            emit_code(fn.prolog_size, kUwopAllocSmall, static_cast<int>(size / 8 - 1));
        } else {
            emit_code(fn.prolog_size, kUwopAllocLarge, 0);
            emit_u16le(slots, static_cast<uint16_t>(size / 8));
            real_slot_count++; // the extra data slot also counts toward CountOfCodes
        }
    }

    emit_code(fn.fpreg_offset, kUwopSetFpreg, 0);

    uint32_t cumulative = 0;
    std::vector<uint32_t> push_end_offset(fn.pushed_before_fpreg.size());
    for (size_t i = 0; i < fn.pushed_before_fpreg.size(); i++) {
        cumulative += static_cast<uint32_t>(push_insn_size(fn.pushed_before_fpreg[i]));
        push_end_offset[i] = cumulative;
    }
    for (size_t i = fn.pushed_before_fpreg.size(); i-- > 0;) {
        emit_code(push_end_offset[i], kUwopPushNonvol, fn.pushed_before_fpreg[i]);
    }

    const size_t padded_slot_count = real_slot_count + (real_slot_count % 2);
    if (padded_slot_count > real_slot_count) emit_u16le(slots, 0); // unused pad slot

    std::vector<uint8_t> out;
    out.push_back(0x01); // Version=1, Flags=0 (UNW_FLAG_NHANDLER)
    out.push_back(static_cast<uint8_t>(fn.prolog_size));
    out.push_back(static_cast<uint8_t>(real_slot_count));
    out.push_back(static_cast<uint8_t>(fn.frame_register & 0xF)); // FrameOffset=0
    out.insert(out.end(), slots.begin(), slots.end());
    return out;
}

} // namespace

std::vector<uint8_t> build_exception_directory(const std::vector<uint8_t> &original_table,
                                                const std::vector<SehFunction> &functions,
                                                uint32_t blob_rva)
{
    std::vector<SehFunction> sorted = functions;
    std::sort(sorted.begin(), sorted.end(),
              [](const SehFunction &a, const SehFunction &b) { return a.rva < b.rva; });

    // sizeof(RUNTIME_FUNCTION) == 12 (BeginAddress, EndAddress, UnwindInfoAddress,
    // each a ULONG/RVA) -- every original entry is already exactly this shape.
    constexpr uint32_t kRuntimeFunctionSize = 12;
    const uint32_t table_size = static_cast<uint32_t>(original_table.size()) +
                                 static_cast<uint32_t>(sorted.size()) * kRuntimeFunctionSize;

    std::vector<std::vector<uint8_t>> unwind_infos;
    unwind_infos.reserve(sorted.size());
    std::vector<uint32_t> unwind_info_rva(sorted.size());
    uint32_t unwind_offset = align_up(table_size, 4);
    for (size_t i = 0; i < sorted.size(); i++) {
        unwind_infos.push_back(build_unwind_info(sorted[i]));
        unwind_info_rva[i] = blob_rva + unwind_offset;
        unwind_offset += static_cast<uint32_t>(unwind_infos[i].size());
    }

    std::vector<uint8_t> out;
    out.reserve(unwind_offset);
    out.insert(out.end(), original_table.begin(), original_table.end());
    for (size_t i = 0; i < sorted.size(); i++) {
        emit_u32le(out, sorted[i].rva);
        emit_u32le(out, sorted[i].rva + sorted[i].size);
        emit_u32le(out, unwind_info_rva[i]);
    }
    out.resize(align_up(table_size, 4), 0);
    for (const auto &ui : unwind_infos) out.insert(out.end(), ui.begin(), ui.end());
    return out;
}

} // namespace karity
