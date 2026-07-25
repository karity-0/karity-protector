#include "asm_obfuscate.h"

#include <cstdint>
#include <cstdio>
#include <vector>

#include "x86_junk.h"

namespace karity {

namespace {

// Left-trim ASCII whitespace for classification (the original line is emitted
// verbatim regardless -- we only inspect a trimmed view).
std::string ltrim(const std::string &s)
{
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) i++;
    return s.substr(i);
}

bool starts_with(const std::string &s, const char *prefix)
{
    size_t n = 0;
    while (prefix[n]) n++;
    return s.size() >= n && s.compare(0, n, prefix) == 0;
}

// A .s line is an *instruction* (a place we may splice junk after) iff, once
// trimmed, it's non-empty and is neither a comment (#...), a directive (.foo),
// nor a label (ends in ':'). GCC -S puts labels -- including local .LNN: ones,
// which trip the directive test first anyway -- on their own lines, so this
// stays simple.
bool is_instruction_line(const std::string &trimmed)
{
    if (trimmed.empty()) return false;
    if (trimmed[0] == '#' || trimmed[0] == '.') return false;
    if (trimmed.back() == ':') return false;
    return true;
}

// Track whether we're inside an executable section. GCC/PE output moves between
// .text (executable) and .data/.bss/.rdata/.rodata (data) via bare directives
// and `.section <name>` -- junk may only go into the former.
void update_section(const std::string &trimmed, bool &in_text)
{
    if (starts_with(trimmed, ".text")) {
        in_text = true;
    } else if (starts_with(trimmed, ".section")) {
        // .section .text.unlikely,... stays executable; anything else is data.
        std::string rest = ltrim(trimmed.substr(sizeof(".section") - 1));
        in_text = starts_with(rest, ".text");
    } else if (starts_with(trimmed, ".data") || starts_with(trimmed, ".bss") ||
               starts_with(trimmed, ".rdata") || starts_with(trimmed, ".rodata")) {
        in_text = false;
    }
    // every other directive (.globl/.p2align/.type/.long/.string/...) leaves
    // the current section unchanged.
}

// Render a self-contained junk byte blob as `.byte 0x..,0x..` lines (chunked
// so no single line runs absurdly long). The assembler places these bytes
// verbatim; because the blob is position-independent (all its internal jumps
// are self-relative), it stays a correct no-op wherever it lands.
void append_bytes_directive(std::string &out, const std::vector<uint8_t> &bytes)
{
    constexpr size_t kPerLine = 16;
    for (size_t i = 0; i < bytes.size(); i += kPerLine) {
        out += "\t.byte ";
        size_t end = i + kPerLine < bytes.size() ? i + kPerLine : bytes.size();
        for (size_t j = i; j < end; j++) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "0x%02x", bytes[j]);
            out += buf;
            if (j + 1 < end) out += ',';
        }
        out += '\n';
    }
}

// One random junk blob using the same generators the injector uses for its
// stubs/interpreter (x86_junk.h). All are strict no-ops; the overlap forms
// additionally desync linear-sweep / recursive-traversal disassemblers, which
// is exactly the point of pushing them down into the blob's own function bodies.
void emit_one_junk(std::vector<uint8_t> &bytes, std::mt19937_64 &rng)
{
    std::uniform_int_distribution<int> pick(0, 8);
    switch (pick(rng)) {
    case 0: emit_native_junk(bytes, rng); break;
    case 1: emit_native_opaque_predicate(bytes, rng); break;
    case 2: emit_junk_call(bytes, rng); break;
    case 3: emit_overlap_jump(bytes, rng); break;
    case 4: emit_overlap_opaque(bytes, rng); break;
    case 5: emit_indirect_jump(bytes, rng); break;
    case 6: emit_stack_noise(bytes, rng); break;
    case 7: emit_antistepover_call(bytes, rng); break;
    default: emit_overlap_midinsn(bytes, rng); break;
    }
}

} // namespace

std::string obfuscate_asm(const std::string &att_asm, std::mt19937_64 &rng, double density)
{
    if (density < 0.0) density = 0.0;
    if (density > 1.0) density = 1.0;
    std::uniform_real_distribution<double> coin(0.0, 1.0);

    std::string out;
    out.reserve(att_asm.size() * 2);

    bool in_text = false;
    size_t pos = 0;
    while (pos <= att_asm.size()) {
        size_t nl = att_asm.find('\n', pos);
        bool last = (nl == std::string::npos);
        std::string line = att_asm.substr(pos, last ? std::string::npos : nl - pos);

        std::string trimmed = ltrim(line);
        update_section(trimmed, in_text);

        out += line;
        if (!last) out += '\n';

        if (in_text && is_instruction_line(trimmed) && coin(rng) < density) {
            std::vector<uint8_t> bytes;
            emit_one_junk(bytes, rng);
            append_bytes_directive(out, bytes);
        }

        if (last) break;
        pos = nl + 1;
    }

    return out;
}

} // namespace karity
