#include "runtime_rewrite.h"

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include "asm_obfuscate.h"
#include "runtime_blob.h"    // static (obfuscation-off) blob + offset macros
#include "runtime_sources.h" // embedded runtime .s/.S + link flags

namespace karity {

namespace {

namespace fs = std::filesystem;

std::string quote(const std::string &s) { return "\"" + s + "\""; }

// Run argv as a single command, redirecting stdout+stderr to `log_path` (or the
// null device when empty). Returns the command's exit code. The whole line is
// wrapped in an extra pair of quotes: cmd.exe strips the outermost quotes, so
// this is the documented way to invoke a quoted program path with quoted args.
int run(const std::vector<std::string> &argv, const std::string &log_path)
{
    std::string cmd;
    for (size_t i = 0; i < argv.size(); i++) {
        if (i) cmd += ' ';
        cmd += quote(argv[i]);
    }
    cmd += " > " + quote(log_path.empty() ? std::string("nul") : log_path) + " 2>&1";
    std::string full = "\"" + cmd + "\"";
    return std::system(full.c_str());
}

std::string read_file(const fs::path &p)
{
    std::ifstream f(p, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

void write_file(const fs::path &p, const std::string &text)
{
    std::ofstream f(p, std::ios::binary);
    f.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!f) throw std::runtime_error("karity: failed writing " + p.string());
}

// nm output: "<hex-vma> <type> <name>". Build name -> vma. mingw x86-64 symbols
// carry no leading underscore (same assumption GenerateBlobHeader.cmake makes).
uint64_t nm_lookup(const std::string &nm_out, const std::string &sym)
{
    std::istringstream ss(nm_out);
    std::string line;
    while (std::getline(ss, line)) {
        std::istringstream ls(line);
        std::string vma, type, name;
        if (!(ls >> vma >> type >> name)) continue;
        if (name == sym) return std::strtoull(vma.c_str(), nullptr, 16);
    }
    throw std::runtime_error("karity: symbol '" + sym + "' not found in recompiled runtime");
}

// objdump -h: each section is a header line ("<idx> <name> <size> <vma> ...")
// followed by a flags line; the flatten base is the lowest VMA among sections
// flagged LOAD -- exactly objcopy -O binary's implicit origin.
uint64_t objdump_lowest_load_vma(const std::string &od_out)
{
    std::istringstream ss(od_out);
    std::string line;
    bool have = false;
    uint64_t lowest = 0;
    uint64_t pending_vma = 0;
    bool pending = false;
    while (std::getline(ss, line)) {
        if (pending && line.find("LOAD") != std::string::npos) {
            if (!have || pending_vma < lowest) { lowest = pending_vma; have = true; }
            pending = false;
            continue;
        }
        pending = false;
        std::istringstream ls(line);
        std::string idx, name, size, vma;
        if (!(ls >> idx >> name >> size >> vma)) continue;
        bool idx_num = !idx.empty();
        for (char c : idx) if (c < '0' || c > '9') idx_num = false;
        if (idx_num && !name.empty() && name[0] == '.') {
            pending_vma = std::strtoull(vma.c_str(), nullptr, 16);
            pending = true;
        }
    }
    if (!have) throw std::runtime_error("karity: no loadable section found in recompiled runtime");
    return lowest;
}

uint32_t offset_of(const std::string &nm_out, uint64_t base, const std::string &sym)
{
    uint64_t vma = nm_lookup(nm_out, sym);
    if (vma < base) throw std::runtime_error("karity: negative offset for '" + sym + "'");
    return static_cast<uint32_t>(vma - base);
}

} // namespace

RuntimeBlobLayout default_runtime_layout()
{
    RuntimeBlobLayout L;
    L.blob.assign(karity_runtime_blob, karity_runtime_blob + KARITY_RUNTIME_BLOB_SIZE);
    L.entry_offset = KARITY_RUNTIME_ENTRY_OFFSET;
    L.thunk_fpreg_offset = KARITY_RUNTIME_THUNK_FPREG_OFFSET;
    L.thunk_prolog_end_offset = KARITY_RUNTIME_THUNK_PROLOG_END_OFFSET;
    L.thunk_end_offset = KARITY_RUNTIME_THUNK_END_OFFSET;
    L.interp_rel32_offset = KARITY_RUNTIME_INTERP_REL32_OFFSET;
    L.native_call_offset = KARITY_RUNTIME_NATIVE_CALL_OFFSET;
    L.native_call_prolog_end_offset = KARITY_RUNTIME_NATIVE_CALL_PROLOG_END_OFFSET;
    L.native_call_end_offset = KARITY_RUNTIME_NATIVE_CALL_END_OFFSET;
    L.nanomite_thunk_offset = KARITY_RUNTIME_NANOMITE_THUNK_OFFSET;
    L.antidebug_thunk_offset = KARITY_RUNTIME_ANTIDEBUG_THUNK_OFFSET;
    L.integrity_thunk_offset = KARITY_RUNTIME_INTEGRITY_THUNK_OFFSET;
    return L;
}

ToolchainPaths resolve_toolchain(const std::string &mingw_bin_override)
{
    std::string dir = mingw_bin_override;
    if (dir.empty()) {
        if (const char *e = std::getenv("KARITY_MINGW_BIN")) dir = e;
    }

    auto mk = [&](const char *tool) -> std::string {
        if (!dir.empty()) return (fs::path(dir) / (std::string(tool) + ".exe")).string();
        return tool; // rely on PATH
    };

    ToolchainPaths tc{mk("gcc"), mk("objcopy"), mk("nm"), mk("objdump")};

    if (run({tc.gcc, "--version"}, "") != 0) {
        throw std::runtime_error(
            "karity: --obf-runtime needs a mingw64 gcc/binutils toolchain, but '" + tc.gcc +
            "' could not be run. Set --mingw-bin <dir> or $KARITY_MINGW_BIN, or put gcc on PATH.");
    }
    return tc;
}

RuntimeBlobLayout build_obfuscated_runtime(std::mt19937_64 &rng, const ToolchainPaths &tc, double density)
{
    std::uniform_int_distribution<uint64_t> tag_dist;
    fs::path work = fs::temp_directory_path() /
                    ("karity_obf_" + std::to_string(tag_dist(rng)));
    std::error_code ec;
    fs::create_directories(work, ec);
    if (ec) throw std::runtime_error("karity: cannot create temp dir " + work.string());

    // --- write (and, where obfuscatable, junk-rewrite) each runtime TU -------
    std::vector<std::string> inputs;
    for (int i = 0; i < karity_runtime_source_count; i++) {
        const KarityRuntimeSource &src = karity_runtime_sources[i];
        std::string text = src.text;
        if (src.is_obfuscatable) text = obfuscate_asm(text, rng, density);
        fs::path p = work / src.name;
        write_file(p, text);
        inputs.push_back(p.string());
    }

    const fs::path image = work / "runtime_image.exe";
    const fs::path blob_bin = work / "runtime_blob.bin";
    const fs::path link_log = work / "link.log";
    const fs::path nm_out = work / "nm.txt";
    const fs::path od_out = work / "objdump.txt";

    // --- link the (rewritten) .s/.S back into a freestanding image -----------
    std::vector<std::string> link = {tc.gcc};
    link.insert(link.end(), inputs.begin(), inputs.end());
    link.push_back("-o");
    link.push_back(image.string());
    for (const char *flag : karity_runtime_link_flags) link.push_back(flag);

    if (run(link, link_log.string()) != 0) {
        std::string log = read_file(link_log);
        throw std::runtime_error("karity: recompiling obfuscated runtime failed:\n" + log +
                                 "\n(left work dir: " + work.string() + ")");
    }

    // --- flatten to raw bytes + re-derive every symbol offset ----------------
    if (run({tc.objcopy, "-O", "binary", image.string(), blob_bin.string()}, link_log.string()) != 0)
        throw std::runtime_error("karity: objcopy on obfuscated runtime failed:\n" + read_file(link_log));
    if (run({tc.nm, image.string()}, nm_out.string()) != 0)
        throw std::runtime_error("karity: nm on obfuscated runtime failed");
    if (run({tc.objdump, "-h", image.string()}, od_out.string()) != 0)
        throw std::runtime_error("karity: objdump on obfuscated runtime failed");

    const std::string nm_text = read_file(nm_out);
    const std::string od_text = read_file(od_out);
    const uint64_t base = objdump_lowest_load_vma(od_text);

    RuntimeBlobLayout L;
    const std::string blob = read_file(blob_bin);
    L.blob.assign(blob.begin(), blob.end());
    if (L.blob.empty()) throw std::runtime_error("karity: recompiled runtime blob is empty");

    L.entry_offset = offset_of(nm_text, base, "karity_vm_thunk");
    L.thunk_fpreg_offset = offset_of(nm_text, base, "karity_vm_thunk_fpreg_offset");
    L.thunk_prolog_end_offset = offset_of(nm_text, base, "karity_vm_thunk_prolog_end");
    L.thunk_end_offset = offset_of(nm_text, base, "karity_vm_thunk_end");
    L.interp_rel32_offset = offset_of(nm_text, base, "karity_interp_rel32");
    L.native_call_offset = offset_of(nm_text, base, "karity_vm_native_call");
    L.native_call_prolog_end_offset = offset_of(nm_text, base, "karity_vm_native_call_prolog_end");
    L.native_call_end_offset = offset_of(nm_text, base, "karity_vm_native_call_end");
    L.nanomite_thunk_offset = offset_of(nm_text, base, "karity_nanomite_install_thunk");
    L.antidebug_thunk_offset = offset_of(nm_text, base, "karity_anti_debug_install_thunk");
    L.integrity_thunk_offset = offset_of(nm_text, base, "karity_integrity_install_thunk");

    fs::remove_all(work, ec); // best-effort cleanup
    return L;
}

} // namespace karity
