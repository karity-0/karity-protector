#include "injector.h"

#include <cstdio>
#include <cstring>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "karity/bytecode_crypt.h"
#include "karity/integrity.h"
#include "karity/isa.h"
#include "karity/nanomite.h"
#include "native/interp_codegen.h"
#include "native/nanomite_encoder.h"
#include "native/nanomite_scan.h"
#include "native/runtime_rewrite.h" // RuntimeBlobLayout (blob bytes + symbol offsets)
#include "native/seh_unwind.h"
#include "native/x86_junk.h"
#include "vm/lifter.h"

namespace karity {

namespace {

constexpr size_t kOepJmpSize = 5;      // E9 rel32: all the OEP patch strictly needs
constexpr size_t kCallQuadsSize = 29;  // E8 rel32 (5) + bytecode delta (8) + exit_target delta (8) + bytecode_key_seed (8)
constexpr size_t kNanomiteCallQuadsSize = 21; // E8 rel32 (5) + site_table delta (8) + site_count (4) + pad (4)
constexpr size_t kAntiDebugCallSize = 13; // E8 rel32 (5) + enabled_categories (4) + pad (4) -- see
                                           // runtime/anti_debug_thunk.S's inline params contract
constexpr size_t kIntegrityCallSize = 21; // E8 rel32 (5) + region delta (8) + region len (8) -- see
                                           // runtime/integrity_thunk.S's inline params contract
constexpr uint32_t kSectionAlign = 16;

uint32_t align_up(uint32_t v, uint32_t a) { return (v + a - 1) / a * a; }

void emit_rel32(std::vector<uint8_t> &out, uint8_t opcode, uint64_t from_va_of_next_insn, uint64_t target_va)
{
    out.push_back(opcode);
    int32_t rel = static_cast<int32_t>(static_cast<int64_t>(target_va) - static_cast<int64_t>(from_va_of_next_insn));
    for (int i = 0; i < 4; i++) out.push_back(static_cast<uint8_t>(rel >> (8 * i)));
}

void emit_call_rel32(std::vector<uint8_t> &out, uint64_t from_va_of_next_insn, uint64_t target_va)
{
    emit_rel32(out, 0xE8, from_va_of_next_insn, target_va);
}

void emit_jmp_rel32(std::vector<uint8_t> &out, uint64_t from_va_of_next_insn, uint64_t target_va)
{
    emit_rel32(out, 0xE9, from_va_of_next_insn, target_va);
}

void emit_u64le(std::vector<uint8_t> &out, uint64_t v)
{
    for (int i = 0; i < 8; i++) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

void emit_u32le(std::vector<uint8_t> &out, uint32_t v)
{
    for (int i = 0; i < 4; i++) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

// A generous run of native junk/opaque-predicate filler -- the machine-code
// counterpart to the bytecode-level obfuscation in vm/obfuscate.h, applied
// right where a real protector's VM entry stub would sit: between the OEP
// jump and the actual `call karity_vm_thunk`. VMProtect/Themida-style entry
// stubs are typically thick with this kind of noise, so this is deliberately
// heavy rather than a token gesture.
std::vector<uint8_t> build_native_stub_prefix(std::mt19937_64 &rng)
{
    std::vector<uint8_t> out;
    std::uniform_int_distribution<int> round_count(8, 20);
    std::uniform_int_distribution<int> kind(0, 7);
    int rounds = round_count(rng);
    for (int i = 0; i < rounds; i++) {
        switch (kind(rng)) {
        case 0: emit_native_junk(out, rng); break;
        case 1: emit_native_opaque_predicate(out, rng); break;
        case 2: emit_overlap_jump(out, rng); break;
        case 3: emit_overlap_opaque(out, rng); break;
        case 4: emit_overlap_midinsn(out, rng); break;
        case 5: emit_indirect_jump(out, rng); break;
        case 6: emit_stack_noise(out, rng); break;
        default: emit_junk_call(out, rng); break;
        }
    }
    return out;
}

// After `call karity_vm_thunk`, control never actually returns here --
// vm_thunk's epilogue `ret`s straight to exit_target instead. That makes
// the space between the call and the bytecode region genuinely dead: free
// room for more junk that, read linearly from the call, looks exactly like
// what runs right after it (down to a trailing `ret` implying a normal
// function boundary -- also never executed).
std::vector<uint8_t> build_unreachable_trailing_junk(std::mt19937_64 &rng)
{
    std::vector<uint8_t> out;
    std::uniform_int_distribution<int> round_count(4, 10);
    std::uniform_int_distribution<int> kind(0, 7);
    int rounds = round_count(rng);
    for (int i = 0; i < rounds; i++) {
        switch (kind(rng)) {
        case 0: emit_native_junk(out, rng); break;
        case 1: emit_native_opaque_predicate(out, rng); break;
        case 2: emit_overlap_jump(out, rng); break;
        case 3: emit_overlap_opaque(out, rng); break;
        case 4: emit_overlap_midinsn(out, rng); break;
        case 5: emit_indirect_jump(out, rng); break;
        case 6: emit_stack_noise(out, rng); break;
        default: emit_junk_call(out, rng); break;
        }
    }
    out.push_back(0xC3); // ret, purely for appearances -- never reached
    return out;
}

// Fills up to `budget` bytes with native junk/opaque-predicate blocks,
// falling back to NOPs once nothing more will fit (junk blocks have variable,
// unpredictable size, and this is often called with only a handful of bytes
// of slack, e.g. leftover space at the OEP after the jump into the stub).
void fill_with_junk_then_nop(std::vector<uint8_t> &out, size_t budget, std::mt19937_64 &rng)
{
    std::uniform_int_distribution<int> kind(0, 7);
    for (;;) {
        std::vector<uint8_t> candidate;
        switch (kind(rng)) {
        case 0: emit_native_junk(candidate, rng); break;
        case 1: emit_native_opaque_predicate(candidate, rng); break;
        case 2: emit_overlap_jump(candidate, rng); break;
        case 3: emit_overlap_opaque(candidate, rng); break;
        case 4: emit_overlap_midinsn(candidate, rng); break;
        case 5: emit_indirect_jump(candidate, rng); break;
        case 6: emit_stack_noise(candidate, rng); break;
        default: emit_junk_call(candidate, rng); break;
        }
        if (out.size() + candidate.size() > budget) break;
        out.insert(out.end(), candidate.begin(), candidate.end());
    }
    while (out.size() < budget) out.push_back(0x90);
}

std::string hex32(uint32_t v)
{
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%X", v);
    return std::string(buf);
}

// One virtualization site's own bookkeeping: its probe/lift result, and its
// [stub_prefix][call thunk + quad][trailing_junk] block within the shared
// section (see the assembly step in inject_vm_at_entry). Site 0 is always
// the OEP; any others come from `extra_entry_rvas`.
struct Site {
    uint32_t rva = 0;
    uint64_t site_va = 0;
    std::vector<uint8_t> probe;
    std::vector<uint8_t> stub_prefix;
    uint64_t entry_stub_va = 0;   // where this site's OEP-style jmp patch lands
    uint32_t params_offset = 0;
    uint64_t params_va = 0;       // this site's own anchor
    LiftResult lifted{};
    std::vector<uint8_t> trailing_junk;
    uint64_t exit_target_va = 0;
    uint32_t bytecode_region_offset = 0;
    uint64_t bytecode_va = 0;
    uint64_t bytecode_key_seed = 0; // this site's XOR-keystream seed, see
                                     // include/karity/bytecode_crypt.h
};

} // namespace

void inject_vm_at_entry(PeImage &img, const RuntimeBlobLayout &layout,
                        const std::vector<uint32_t> &extra_entry_rvas, bool skip_oep,
                        uint32_t anti_analysis_categories, bool anti_tamper)
{
    constexpr size_t kMaxProbe = 256;

    // OEP is usually CRT startup code that branches into main() almost
    // immediately -- often close enough that OEP's own probe window
    // unavoidably overlaps a real function's, making it impossible to
    // virtualize both at once (see the overlap check below). skip_oep lets
    // a caller who only cares about specific functions leave OEP alone
    // entirely rather than forcing it in as a low-value, conflict-prone
    // site 0.
    std::vector<uint32_t> site_rvas;
    if (!skip_oep) {
        site_rvas.push_back(img.entry_point_rva());
    }
    site_rvas.insert(site_rvas.end(), extra_entry_rvas.begin(), extra_entry_rvas.end());
    if (site_rvas.empty()) {
        throw std::runtime_error("karity: no virtualization sites (OEP skipped and no extra entries given)");
    }

    // Two sites whose probe windows overlap would mean lifting/patching the
    // same original bytes under two different (possibly conflicting)
    // interpretations -- reject up front rather than trying to reconcile
    // that, same stance the lifter/nanomite scanner already take toward
    // conflicting edges.
    for (size_t i = 0; i < site_rvas.size(); i++) {
        for (size_t j = i + 1; j < site_rvas.size(); j++) {
            const uint64_t a = site_rvas[i], b = site_rvas[j];
            const bool overlap = (a < b + kMaxProbe) && (b < a + kMaxProbe);
            if (overlap) {
                throw std::runtime_error("karity: virtualization sites at RVA " + hex32(site_rvas[i]) +
                                          " and " + hex32(site_rvas[j]) + " have overlapping probe windows");
            }
        }
    }

    std::vector<Site> sites(site_rvas.size());
    for (size_t i = 0; i < site_rvas.size(); i++) {
        sites[i].rva = site_rvas[i];
        sites[i].site_va = img.rva_to_va(site_rvas[i]);
        sites[i].probe = img.read_at_rva(site_rvas[i], kMaxProbe);
    }

    // --- lay out the new section's *shape* before we know any bytecode ----
    // (peek_next_section_rva is independent of content length, so every VA
    // the bytecode needs -- thunk_va, each site's own anchor -- can be
    // computed before lifting decides how big any of it actually is)
    std::mt19937_64 stub_rng(std::random_device{}());

    // One random opcode<->byte permutation for this whole protect run,
    // shared by every site's bytecode (try_lift, below) and the one shared
    // interpreter (generate_interpreter, below) -- they must agree with
    // each other, but a different invocation of the protector gets a
    // different mapping (see include/karity/opcode_map.h).
    const OpcodeMap opcode_map(stub_rng);

    const uint32_t predicted_section_rva = img.peek_next_section_rva();
    const uint64_t section_va = img.rva_to_va(predicted_section_rva);

    const uint64_t thunk_va = section_va + layout.entry_offset;
    const uint64_t native_call_va = section_va + layout.native_call_offset;
    const uint64_t nanomite_thunk_va = section_va + layout.nanomite_thunk_offset;
    const uint64_t anti_debug_thunk_va = section_va + layout.antidebug_thunk_offset;
    const uint64_t integrity_thunk_va = section_va + layout.integrity_thunk_offset;
    const uint32_t stub_offset = align_up(static_cast<uint32_t>(layout.blob.size()), kSectionAlign);

    // Self-integrity ("anti-tamper", include/karity/integrity.h) is opt-in via
    // --anti-tamper. When on, an install call (runtime/integrity_thunk.S) is
    // spliced into the OEP stub right after the anti-analysis one, so it takes
    // up kIntegrityCallSize bytes that everything after it is offset by; when
    // off, no call is emitted, key quads stay plain, and karity_integrity_taint
    // stays 0 so vm_thunk.S's XOR is a no-op. kIntegrityCallEff folds that
    // "present or not" into every offset below.
    const uint32_t kIntegrityCallEff = anti_tamper ? static_cast<uint32_t>(kIntegrityCallSize) : 0;

    // The anti-analysis install call (runtime/anti_debug_thunk.S) sits at
    // the very first byte of the *first* site's (OEP's) stub -- even before
    // the nanomite install call right after it -- for the same "no visible
    // setup moment" reason nanomite's own comment below gives, and because
    // the background watchdog it spawns (include/karity/anti_debug.h) should
    // be live as early into the protected program's lifetime as possible. It
    // carries 8 bytes of inline params after its call (the enabled-categories
    // bitmask + pad, see kAntiDebugCallSize and runtime/anti_debug_thunk.S),
    // so everything after it -- including the nanomite call -- is offset by
    // the full kAntiDebugCallSize.
    const uint32_t anti_debug_call_offset = stub_offset;

    // The integrity install call (runtime/integrity_thunk.S) sits right after
    // the anti-analysis one (only when --anti-tamper -- see kIntegrityCallEff),
    // for the same "as early as possible, no visible setup moment" reasons: its
    // watchdog should be re-hashing as soon into the program's life as it can,
    // and every VM entry after this point relies on the checksum it publishes.
    // Its 16 inline-param bytes (region delta + len) follow its own E8 rel32.
    const uint32_t integrity_call_offset = stub_offset + static_cast<uint32_t>(kAntiDebugCallSize);
    const uint32_t integrity_params_offset = integrity_call_offset + 5;
    const uint64_t integrity_params_va = section_va + integrity_params_offset;

    // The nanomite install call (runtime/nanomite_thunk.S) sits right after
    // that, still before any junk -- it runs silently before anything else in
    // the protected program does, so there's no visible "setup" moment for
    // analysis to notice, and by the time any nanomite-protected code is
    // reached the handler is already active. Only OEP is guaranteed to run
    // exactly once early on, so it's the only site routed through any of
    // these; extra sites (which may be called many times) jump straight to
    // their own stub_prefix instead.
    const uint32_t nanomite_params_offset =
        stub_offset + static_cast<uint32_t>(kAntiDebugCallSize) + kIntegrityCallEff + 5;
    const uint64_t nanomite_anchor_va = section_va + nanomite_params_offset;

    // --- per-site stub blocks, one after another: [stub_prefix][call thunk
    // + quad][trailing_junk]. This is where each site's own try_lift() runs,
    // since each needs its own anchor (this block's own params_va) before it
    // can produce anchor-relative bytecode.
    uint32_t offset = stub_offset + static_cast<uint32_t>(kAntiDebugCallSize) + kIntegrityCallEff +
                       static_cast<uint32_t>(kNanomiteCallQuadsSize);
    for (size_t i = 0; i < sites.size(); i++) {
        Site &s = sites[i];
        s.stub_prefix = build_native_stub_prefix(stub_rng);
        const uint32_t stub_prefix_offset = offset;
        s.entry_stub_va = (i == 0) ? (section_va + stub_offset) : (section_va + stub_prefix_offset);
        offset += static_cast<uint32_t>(s.stub_prefix.size());

        const uint32_t call_site_offset = offset;
        s.params_offset = call_site_offset + 5;
        s.params_va = section_va + s.params_offset;

        auto lifted = try_lift(s.probe.data(), s.probe.size(), kOepJmpSize, s.site_va, s.params_va, opcode_map);
        if (!lifted) {
            throw std::runtime_error("karity: could not lift a virtualizable instruction run at RVA " +
                                      hex32(s.rva) + " (unsupported instruction, or fewer than " +
                                      std::to_string(kOepJmpSize) + " recognizable bytes before something unrecognized)");
        }
        s.lifted = std::move(*lifted);
        s.exit_target_va = img.rva_to_va(s.rva + static_cast<uint32_t>(s.lifted.consumed_bytes));

        // Encrypt this site's bytecode at rest ("opcode rolling decryption",
        // see look/todo.md section C and include/karity/bytecode_crypt.h) --
        // one random seed per site, drawn from the same per-protect-run RNG
        // as stub_prefix/trailing_junk/nanomite scanning above. Only the
        // code region past karity_program_hdr is encrypted; the header
        // itself (magic/isa_ver/code_size/entry_off) is never read through
        // the interpreter's decrypting fetch path, so it stays plaintext.
        // base_offset=0: logical bytecode offset 0 is always this site's
        // first opcode byte.
        s.bytecode_key_seed = stub_rng();
        karity_bytecode_xor_crypt(s.lifted.bytecode.data() + sizeof(karity_program_hdr),
                                   s.lifted.bytecode.size() - sizeof(karity_program_hdr),
                                   0, s.bytecode_key_seed);

        s.trailing_junk = build_unreachable_trailing_junk(stub_rng);

        offset = s.params_offset + static_cast<uint32_t>(kCallQuadsSize - 5) + static_cast<uint32_t>(s.trailing_junk.size());
    }

    // The interpreter itself (dispatch loop + every opcode handler) is
    // generated fresh here rather than reused from a precompiled blob --
    // see native/interp_codegen.h. It's shared by every site (it has no
    // notion of "which site" invoked it), so it's built once, right after
    // every site's own stub block, same relative position as the single-site
    // case it generalizes.
    const uint32_t interp_offset = align_up(offset, kSectionAlign);
    const uint64_t interp_va = section_va + interp_offset;
    // Delta from interp_va, not from any site's anchor: karity_vm_native_call
    // and this interpreter both live at fixed, site-independent offsets
    // within the same shared blob, so this must not depend on which site's
    // anchor happens to be live in ctx when a given VOP_CALL runs -- see
    // interp_codegen.h.
    size_t interp_prolog_size = 0;
    const std::vector<uint8_t> interp_code =
        generate_interpreter(native_call_va - interp_va, stub_rng, opcode_map, &interp_prolog_size);

    // Self-integrity checksum (include/karity/integrity.h): hash the finalized
    // interpreter bytes now, while they're in hand. This is the value the
    // runtime folds back out of every site's key on each VM entry, so it must
    // be computed over *exactly* the bytes that end up in the image -- and
    // nothing patches the interpreter region after this point (the nanomite
    // params/site-table and SEH splices land elsewhere; karity_interp_rel32
    // sits in the runtime blob, not here; the interpreter's own native-call
    // reference is already PIC-baked into interp_code). The one region chosen
    // is the interpreter itself: the crown jewel an attacker must patch to
    // defeat the VM, and conveniently self-contained (it holds no key quads, so
    // there's no circular dependency between the hash and the seeds it keys).
    // When --anti-tamper is off, integrity_hash stays 0 and every use below is
    // a no-op. See runtime/integrity.c for the runtime (live-hash) half.
    const uint64_t integrity_hash =
        anti_tamper ? karity_integrity_hash(interp_code.data(), interp_code.size()) : 0;

    // --- per-site bytecode regions, back-to-back right after the interpreter ---
    uint32_t bytecode_offset = align_up(interp_offset + static_cast<uint32_t>(interp_code.size()), kSectionAlign);
    for (Site &s : sites) {
        s.bytecode_region_offset = bytecode_offset;
        s.bytecode_va = section_va + s.bytecode_region_offset + sizeof(karity_program_hdr);
        bytecode_offset = align_up(
            s.bytecode_region_offset + static_cast<uint32_t>(sizeof(karity_program_hdr)) +
                static_cast<uint32_t>(s.lifted.bytecode.size()),
            kSectionAlign);
    }

    // --- nanomite: scan for a run of straight-line, position-independent
    // code after everything the VM just lifted, independently at *every*
    // site (not just site 0/OEP -- an --entry site is usually main() or
    // similar, exactly the kind of real logic nanomite is meant to cover,
    // unlike OEP's usually-low-value CRT startup code). Each site starts its
    // own scan at its own max_probe_offset, not consumed_bytes: once the
    // lifter can follow branches/loops (see src/vm/lifter.h), a block past
    // the mandatory entry prefix is never physically overwritten -- its
    // original bytes are just orphaned in the image -- so anything in
    // [consumed_bytes, max_probe_offset) may still be a live VOP_VMEXIT_REL
    // target, and re-encoding it here would corrupt that exit. Best-effort:
    // real CRT startup code branches almost immediately, so OEP in
    // particular often finds little or nothing to protect right here -- see
    // src/native/nanomite_scan.h. All sites' resulting entries are
    // concatenated into one shared table below: runtime/nanomite_veh.c looks
    // up a faulting RIP with a flat linear scan over the whole table and
    // doesn't care which site an entry came from, and different sites' probe
    // windows are already guaranteed non-overlapping (see the overlap check
    // above), so their nanomite sub-regions (subsets of those windows) can't
    // collide either.
    std::mt19937_64 nanomite_rng(std::random_device{}());
    std::vector<std::optional<NanomiteScanResult>> nanomite_scans(sites.size());
    for (size_t i = 0; i < sites.size(); i++) {
        const Site &s = sites[i];
        const uint32_t nanomite_scan_offset = static_cast<uint32_t>(s.lifted.max_probe_offset);
        const uint64_t nanomite_scan_va = img.rva_to_va(s.rva + nanomite_scan_offset);
        if (nanomite_scan_offset < s.probe.size()) {
            nanomite_scans[i] = scan_nanomite_region(s.probe.data() + nanomite_scan_offset,
                                                       s.probe.size() - nanomite_scan_offset,
                                                       nanomite_scan_va, nanomite_anchor_va, nanomite_rng);
        }
    }

    // --- assemble the section: [runtime blob][nanomite install call+params]
    // [per-site: stub_prefix + call thunk+quad + trailing_junk][interpreter]
    // [per-site bytecode regions][nanomite site table] ---
    std::vector<uint8_t> section;
    section.insert(section.end(), layout.blob.begin(), layout.blob.end());

    // karity_interp_rel32 (see runtime/vm_thunk.S) has no link-time symbol
    // to resolve against, since the interpreter it calls doesn't exist
    // until this run -- patch the call's rel32 displacement directly into
    // the copied blob. Direct call, not indirect through a data pointer:
    // an indirect call into freshly-injected code was observed to fault at
    // runtime (see vm_thunk.S), even though every direct jmp/call
    // elsewhere in this project has always worked.
    {
        const uint64_t rel32_operand_va = section_va + layout.interp_rel32_offset;
        const int32_t rel = static_cast<int32_t>(static_cast<int64_t>(interp_va) -
                                                  static_cast<int64_t>(rel32_operand_va + 4));
        for (int i = 0; i < 4; i++) {
            section[layout.interp_rel32_offset + i] = static_cast<uint8_t>(static_cast<uint32_t>(rel) >> (8 * i));
        }
    }

    section.resize(stub_offset, 0);

    // anti-analysis install call: the call's return address points at its
    // own 8-byte inline params (enabled_categories + pad, see runtime/
    // anti_debug_thunk.S), and the thunk jmp's past them to continue into
    // the nanomite install call right after. enabled_categories is the
    // --anti-debug/--anti-vm bitmask; 0 (neither flag) still leaves the
    // always-on anti-sandbox checks running (see include/karity/anti_debug.h).
    emit_call_rel32(section, section_va + anti_debug_call_offset + 5, anti_debug_thunk_va);
    emit_u32le(section, anti_analysis_categories);
    emit_u32le(section, 0);

    // integrity install call (only with --anti-tamper): the call's return
    // address points at its own 16-byte inline params (region delta + len, see
    // runtime/integrity_thunk.S), and the thunk jmp's past them to continue
    // into the nanomite install call right after. The region is the generated
    // interpreter [interp_va, interp_va+interp_code.size()); its base is stored
    // as a delta from these params (base-independent under ASLR, same as every
    // other cross-.kvm reference here), reconstructed at runtime as params +
    // delta. When off, no bytes are emitted here and the anti-analysis thunk's
    // continue point lands directly on the nanomite call (kIntegrityCallEff==0).
    if (anti_tamper) {
        emit_call_rel32(section, integrity_params_va, integrity_thunk_va);
        emit_u64le(section, interp_va - integrity_params_va);
        emit_u64le(section, static_cast<uint64_t>(interp_code.size()));
    }

    // nanomite install call: falls straight through into site 0's
    // stub_prefix junk below once karity_nanomite_install returns
    // (runtime/nanomite_thunk.S). site_table_delta/site_count are
    // placeholder zero here, patched in below once the site table's own
    // final position (after every site's bytecode) is known.
    emit_call_rel32(section, section_va + nanomite_params_offset, nanomite_thunk_va);
    emit_u64le(section, 0);
    emit_u32le(section, 0);
    emit_u32le(section, 0);

    for (Site &s : sites) {
        section.insert(section.end(), s.stub_prefix.begin(), s.stub_prefix.end());

        // bytecode_va/exit_target_va are stored as deltas from `params`
        // (this call's own return address, i.e. this site's own anchor),
        // not absolute VAs: this patch has no PE base relocation entry, so
        // if the loader rebases the image (ASLR), a baked-in absolute VA
        // would go stale. A delta from an address that itself shifts by
        // the same rebasing amount stays correct. See runtime/vm_thunk.S
        // for the reader side of this contract.
        emit_call_rel32(section, s.params_va, thunk_va);
        emit_u64le(section, s.bytecode_va - s.params_va);
        emit_u64le(section, s.exit_target_va - s.params_va);
        // Stored key = real_seed ^ integrity_hash. The bytecode itself was
        // encrypted with real_seed (above); at runtime vm_thunk.S XORs the live
        // interpreter checksum back in, recovering real_seed iff the
        // interpreter is pristine (integrity_hash == 0 when --anti-tamper is
        // off, so this is just real_seed then). See include/karity/integrity.h.
        emit_u64le(section, s.bytecode_key_seed ^ integrity_hash); // raw, not params-relative -- see runtime/vm_thunk.S
        section.insert(section.end(), s.trailing_junk.begin(), s.trailing_junk.end());
    }

    section.resize(interp_offset, 0);
    section.insert(section.end(), interp_code.begin(), interp_code.end());

    for (Site &s : sites) {
        section.resize(s.bytecode_region_offset, 0);
        section.insert(section.end(), s.lifted.bytecode.begin(), s.lifted.bytecode.end());
    }

    // nanomite site table, appended right after every site's bytecode --
    // same ASLR-safe delta-from-anchor reasoning as everything else here
    // (see include/karity/nanomite.h). This is what the placeholder params
    // written above get patched to point at. Every virtualization site's
    // scan results are flattened into this one table (see the scan step
    // above for why that's safe).
    const uint32_t nanomite_sites_offset = align_up(static_cast<uint32_t>(section.size()), kSectionAlign);
    const uint64_t nanomite_sites_va = section_va + nanomite_sites_offset;
    uint32_t nanomite_site_count = 0;

    section.resize(nanomite_sites_offset, 0);
    for (const auto &scan : nanomite_scans) {
        if (!scan) continue;
        for (const karity_nanomite_site &site : scan->sites) {
            const auto *raw = reinterpret_cast<const uint8_t *>(&site);
            section.insert(section.end(), raw, raw + sizeof(site));
            nanomite_site_count++;
        }
    }

    {
        const uint64_t site_table_delta = nanomite_sites_va - nanomite_anchor_va;
        for (int i = 0; i < 8; i++) {
            section[nanomite_params_offset + i] = static_cast<uint8_t>(site_table_delta >> (8 * i));
        }
        for (int i = 0; i < 4; i++) {
            section[nanomite_params_offset + 8 + i] = static_cast<uint8_t>(nanomite_site_count >> (8 * i));
        }
    }

    // --- SEH: splice RUNTIME_FUNCTION/UNWIND_INFO entries for the three
    // injected functions (karity_vm_thunk, karity_vm_native_call, the one
    // shared interpreter) into a copy of the image's own Exception Directory,
    // appended right after the nanomite site table -- so Windows can unwind
    // *through* them when an exception needs to reach the original program's
    // own __try/__except or vectored handler from deep inside an outbound
    // VOP_CALL/CALL_IND target. See runtime/vm_thunk.S's "SEH/exception
    // interaction" header paragraph and src/native/seh_unwind.h for why this
    // is needed and how the three functions' shapes map onto it.
    const uint32_t seh_blob_offset = align_up(static_cast<uint32_t>(section.size()), kSectionAlign);
    const uint32_t seh_blob_rva = predicted_section_rva + seh_blob_offset;
    uint32_t seh_table_size = 0;
    {
        std::vector<SehFunction> fns;
        // karity_vm_thunk: pushes the caller's real rbp, establishes RBP as its
        // SEH frame pointer, then does a *fixed* sub rsp,4096 before its one
        // outbound call (to the interpreter). Per the real RtlVirtualUnwind
        // algorithm (codes applied in array order, UWOP_SET_FPREG *un-
        // conditionally overwrites* Rsp from the frame register -- see
        // src/native/seh_unwind.cpp), any UWOP_ALLOC_* code placed *before*
        // SET_FPREG in array order is a no-op for steady-state unwinding
        // regardless of its value, since SET_FPREG discards whatever it did
        // to Rsp -- so the sub rsp,4096 (like the dynamic `and rsp,-16` and
        // Win64-shadow-space `sub rsp,32` that follow it) needs no unwind
        // code at all, exactly like the generated interpreter's own
        // transient `sub rsp,40`/`add rsp,40` bracket.
        fns.push_back({predicted_section_rva + layout.entry_offset,
                        layout.thunk_end_offset - layout.entry_offset,
                        {5} /* RBP, see runtime/vm_thunk.S */,
                        layout.thunk_fpreg_offset - layout.entry_offset,
                        0,
                        layout.thunk_fpreg_offset - layout.entry_offset,
                        5 /* RBP, see runtime/vm_thunk.S */});
        // karity_vm_native_call: no fixed alloc after establishing its frame
        // pointer -- its rsp change (the swap to vreg[RSP]) is an outright
        // overwrite to an unrelated value, not a fixed-size sub, and (like
        // vm_thunk's later dynamic realignment) needs no unwind code either.
        fns.push_back({predicted_section_rva + layout.native_call_offset,
                        layout.native_call_end_offset - layout.native_call_offset,
                        {3, 5, 6, 7} /* RBX, RBP, RSI, RDI push order, see runtime/vm_call.S */,
                        layout.native_call_prolog_end_offset - layout.native_call_offset,
                        0,
                        layout.native_call_prolog_end_offset - layout.native_call_offset,
                        3 /* RBX, see runtime/vm_call.S */});
        // The generated interpreter: its own `sub rsp,40`/`add rsp,40` bracket
        // (VOP_CALL/CALL_IND's align+shadow-space dance around their outbound
        // call) is transient and deep in the dispatch loop, not part of any
        // "prologue" shape -- unlike vm_thunk's, it needs no unwind code.
        fns.push_back({predicted_section_rva + interp_offset,
                        static_cast<uint32_t>(interp_code.size()),
                        {5} /* RBP -- the generated interpreter also pushes its caller's (vm_thunk's)
                               real rbp before establishing its own frame pointer, see
                               interp_codegen.cpp's prologue */,
                        static_cast<uint32_t>(interp_prolog_size),
                        0,
                        static_cast<uint32_t>(interp_prolog_size),
                        5 /* RBP, see interp_codegen.cpp's prologue */});

        const std::vector<uint8_t> original_table = img.read_exception_directory();
        seh_table_size = static_cast<uint32_t>(original_table.size()) +
                          static_cast<uint32_t>(fns.size()) * 12u; // sizeof(RUNTIME_FUNCTION)
        const std::vector<uint8_t> exdir = build_exception_directory(original_table, fns, seh_blob_rva);
        section.resize(seh_blob_offset, 0);
        section.insert(section.end(), exdir.begin(), exdir.end());
    }

    const uint32_t section_rva = img.add_section(".kvm", section,
        /*IMAGE_SCN_CNT_CODE*/ 0x00000020u |
        /*IMAGE_SCN_MEM_EXECUTE*/ 0x20000000u |
        /*IMAGE_SCN_MEM_READ*/ 0x40000000u |
        // nanomite_veh.c's install/handler state (g_sites, g_scratch, ...)
        // is the first mutable global state this runtime blob has ever
        // needed -- everything before it (vm_thunk/vm_call/the generated
        // interpreter) was purely stack-based. Without MEM_WRITE, writing
        // to those globals faults on this section's now-read-only pages.
        /*IMAGE_SCN_MEM_WRITE*/ 0x80000000u);
    if (section_rva != predicted_section_rva) {
        throw std::runtime_error("karity: internal error -- predicted section RVA didn't match (layout bug)");
    }

    img.set_exception_directory(seh_blob_rva, seh_table_size);

    // --- each site just jumps into its own stub; fill any slack with more junk ---
    std::mt19937_64 oep_rng(std::random_device{}());
    for (Site &s : sites) {
        std::vector<uint8_t> patch;
        emit_jmp_rel32(patch, s.site_va + 5, s.entry_stub_va);
        fill_with_junk_then_nop(patch, s.lifted.consumed_bytes, oep_rng);
        img.write_at_rva(s.rva, patch.data(), patch.size());
    }

    // Overwrite each site's nanomite-eligible run right after everything the
    // lifter touched there, in-place with [trap marker][ciphertext] blocks --
    // same length as the original bytes, nothing else moves.
    for (size_t i = 0; i < sites.size(); i++) {
        if (!nanomite_scans[i]) continue;
        const uint32_t scan_offset = static_cast<uint32_t>(sites[i].lifted.max_probe_offset);
        img.write_at_rva(sites[i].rva + scan_offset,
                          nanomite_scans[i]->patched_bytes.data(), nanomite_scans[i]->patched_bytes.size());
    }
}

} // namespace karity
