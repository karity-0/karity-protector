#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>
#include <vector>

#include "inject/injector.h"
#include "pe/pe_image.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::fprintf(stderr,
            "usage: %s <input.exe> [-o <output.exe>] [--entry <hex-rva>]... [--no-oep] "
            "[--anti-ida] [--anti-ida-rva <hex-rva>] [--anti-ida-size <hex-size>]\n",
            argv[0]);
        return 2;
    }

    std::string in_path = argv[1];
    std::string out_path = in_path + ".karity.exe";
    std::vector<uint32_t> extra_entries;
    bool skip_oep = false;
    bool anti_ida = false;
    bool anti_ida_rva_set = false;
    uint32_t anti_ida_rva = 0;
    uint32_t anti_ida_size = 0;
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-o" && i + 1 < argc) {
            out_path = argv[++i];
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
        auto img = karity::PeImage::load(in_path);
        karity::inject_vm_at_entry(img, extra_entries, skip_oep);
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
