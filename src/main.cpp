#include <cstdio>
#include <cstdlib>
#include <exception>
#include <random>
#include <string>
#include <vector>

#include "inject/injector.h"
#include "karity/anti_debug.h"
#include "native/runtime_rewrite.h"
#include "pe/pe_image.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::fprintf(stderr,
            "usage: %s <input.exe> [-o <output.exe>] [--entry <hex-rva>]... [--no-oep] "
            "[--anti-debug] [--anti-vm] [--anti-sandbox] [--anti-tamper] "
            "[--obf-runtime] [--mingw-bin <dir>] "
            "[--anti-ida] [--anti-ida-rva <hex-rva>] [--anti-ida-size <hex-size>]\n",
            argv[0]);
        return 2;
    }

    std::string in_path = argv[1];
    std::string out_path = in_path + ".karity.exe";
    std::vector<uint32_t> extra_entries;
    bool skip_oep = false;
    uint32_t anti_analysis = 0;
    bool anti_tamper = false;
    bool obf_runtime = false;
    std::string mingw_bin;
    bool anti_ida = false;
    bool anti_ida_rva_set = false;
    uint32_t anti_ida_rva = 0;
    uint32_t anti_ida_size = 0;
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-o" && i + 1 < argc) {
            out_path = argv[++i];
        } else if (arg == "--anti-debug") {
            // Fold debugger-presence checks into the bytecode decryption key
            // (see include/karity/anti_debug.h). Opt-in: a real end user is
            // essentially never being debugged, but this is off by default
            // alongside --anti-vm so the two false-positive-prone categories
            // stay explicit. Anti-sandbox runs regardless.
            anti_analysis |= KARITY_ANTI_ANALYSIS_DEBUG;
        } else if (arg == "--anti-vm") {
            // Fold hypervisor-presence checks into the same key. Opt-in
            // specifically because a large, legitimate fraction of real
            // deployments run inside a VM (cloud/VDI/Parallels/CI) and would
            // otherwise be corrupted -- see include/karity/anti_debug.h.
            anti_analysis |= KARITY_ANTI_ANALYSIS_VM;
        } else if (arg == "--anti-sandbox") {
            // Fold automated-sandbox heuristics (Sandboxie DLL, low CPU/RAM,
            // fresh boot, hooked Sleep) into the same key. Opt-in like the
            // others -- its Sleep-skew probe also costs ~300ms at startup, so
            // it shouldn't be forced on. See include/karity/anti_debug.h.
            anti_analysis |= KARITY_ANTI_ANALYSIS_SANDBOX;
        } else if (arg == "--anti-tamper") {
            // Self-integrity: hash the generated interpreter and fold that
            // checksum into every site's bytecode decryption key, so patching
            // the interpreter corrupts decryption rather than tripping a
            // defeatable branch (see include/karity/integrity.h). Unlike the
            // anti-analysis categories this has no legitimate-use false
            // positives -- the image's own bytes are identical for every user
            // -- so it's safe to leave on, but kept an explicit opt-in for
            // uniformity with the others.
            anti_tamper = true;
        } else if (arg == "--entry" && i + 1 < argc) {
            // Additional virtualization site, beyond OEP (unless --no-oep) --
            // an RVA the caller already knows points at a liftable function
            // entry (see inject_vm_at_entry's doc comment). No function
            // discovery of our own is done.
            extra_entries.push_back(static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 16)));
        } else if (arg == "--no-oep") {
            // Don't virtualize OEP at all -- useful when it's just CRT
            // startup code whose probe window would otherwise unavoidably
            // overlap a real --entry target's (see inject_vm_at_entry).
            skip_oep = true;
        } else if (arg == "--obf-runtime") {
            // Recompile the runtime blob with per-instruction junk this protect
            // run, so the anti-debug/vm/sandbox scans and other .c-derived blob
            // functions are no longer plainly readable in IDA (see
            // native/runtime_rewrite.h). Needs a mingw64 gcc/binutils toolchain
            // at protect time (--mingw-bin / $KARITY_MINGW_BIN / PATH).
            obf_runtime = true;
        } else if (arg == "--mingw-bin" && i + 1 < argc) {
            // Directory holding gcc/objcopy/nm/objdump for --obf-runtime.
            mingw_bin = argv[++i];
        } else if (arg == "--anti-ida") {
            // Spoof IMAGE_DIRECTORY_ENTRY_IAT to point at the (post-
            // injection) entry point, tricking IDA into classifying it as
            // an extern/_idata segment. See PeImage::spoof_iat_directory.
            anti_ida = true;
        } else if (arg == "--anti-ida-rva" && i + 1 < argc) {
            anti_ida = true;
            anti_ida_rva_set = true;
            anti_ida_rva = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 16));
        } else if (arg == "--anti-ida-size" && i + 1 < argc) {
            anti_ida_size = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 16));
        }
    }

    try {
        karity::RuntimeBlobLayout layout;
        if (obf_runtime) {
            std::mt19937_64 rng(std::random_device{}());
            karity::ToolchainPaths tc = karity::resolve_toolchain(mingw_bin);
            layout = karity::build_obfuscated_runtime(rng, tc);
        } else {
            layout = karity::default_runtime_layout();
        }

        auto img = karity::PeImage::load(in_path);
        karity::inject_vm_at_entry(img, layout, extra_entries, skip_oep, anti_analysis, anti_tamper);
        if (anti_ida) {
            const uint32_t rva = anti_ida_rva_set ? anti_ida_rva : img.entry_point_rva();
            img.spoof_iat_directory(rva, anti_ida_size);
        }
        img.save(out_path);
        std::printf("karity: wrote %s\n", out_path.c_str());
        return 0;
    } catch (const std::exception &e) {
        std::fprintf(stderr, "karity: error: %s\n", e.what());
        return 1;
    }
}
