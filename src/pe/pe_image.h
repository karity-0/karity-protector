#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <windows.h>

namespace karity {

// Minimal PE64 (x86-64) reader/writer: enough to append one new section and
// redirect the entry point. Not a general-purpose PE library -- no support
// for rich headers, signed images, .NET metadata, or images too tight on
// header space to fit another section entry.
class PeImage {
public:
    static PeImage load(const std::string &path);
    void save(const std::string &path) const;

    uint32_t entry_point_rva() const { return nt_.OptionalHeader.AddressOfEntryPoint; }
    void set_entry_point_rva(uint32_t rva) { nt_.OptionalHeader.AddressOfEntryPoint = rva; }
    uint64_t image_base() const { return nt_.OptionalHeader.ImageBase; }
    uint64_t rva_to_va(uint32_t rva) const { return image_base() + rva; }

    // Reads `len` bytes of file content starting at `rva`. `rva` must fall
    // within a single existing section's raw data.
    std::vector<uint8_t> read_at_rva(uint32_t rva, size_t len) const;

    // Overwrites `len` bytes of file content starting at `rva` in place.
    void write_at_rva(uint32_t rva, const uint8_t *data, size_t len);

    // Appends a new section containing `content`, zero-padded up to a
    // multiple of FileAlignment/SectionAlignment. Returns the section's RVA.
    uint32_t add_section(const std::string &name, const std::vector<uint8_t> &content, uint32_t characteristics);

    // Returns the RVA a section added *right now* would get, without
    // actually adding one. Content that needs to embed anchor/target
    // addresses relative to its own eventual section (see the injector)
    // has to know this before its final bytes -- and therefore its final
    // length -- are decided, so this must not depend on content size.
    uint32_t peek_next_section_rva() const;

    // Overwrites the IMAGE_DIRECTORY_ENTRY_IAT data directory (Optional
    // Header) to claim `rva`/`size` is the import address table. The
    // Windows loader never consults this entry when resolving imports (it
    // walks the Import Directory Table's thunk chains instead), so this is
    // a no-op at runtime -- but IDA's PE loader trusts it and reclassifies
    // the range as an extern/_idata segment, blocking disassembly and
    // decompilation of whatever code actually lives there.
    // `size` of 0 means "from rva to the end of its containing section"
    // (guarantees the whole target function/site is covered).
    void spoof_iat_directory(uint32_t rva, uint32_t size = 0);

    // Reads the image's *actual* Exception Directory (IMAGE_DIRECTORY_ENTRY_
    // EXCEPTION) -- the RUNTIME_FUNCTION table x64 SEH unwinding depends on --
    // as raw bytes. Empty if the image has none (Size == 0). Unlike
    // spoof_iat_directory, this directory is genuinely consulted by the OS at
    // runtime (RtlLookupFunctionEntry), so callers that repoint it (see
    // set_exception_directory below) must supply a real, valid replacement
    // table, not a decoy.
    std::vector<uint8_t> read_exception_directory() const;

    // Repoints IMAGE_DIRECTORY_ENTRY_EXCEPTION at a real, already-assembled
    // RUNTIME_FUNCTION table (see src/native/seh_unwind.h) -- used once new
    // code (the injected VM thunk/native-call/interpreter, see
    // src/inject/injector.cpp) needs entries the original table didn't have.
    void set_exception_directory(uint32_t rva, uint32_t size);

private:
    static uint32_t align_up(uint32_t value, uint32_t alignment);
    int section_index_for_rva(uint32_t rva) const;

    IMAGE_DOS_HEADER dos_{};
    std::vector<uint8_t> dos_stub_; // everything between the DOS header and e_lfanew
    IMAGE_NT_HEADERS64 nt_{};
    std::vector<IMAGE_SECTION_HEADER> section_headers_;
    std::vector<std::vector<uint8_t>> section_data_; // raw (on-disk) bytes, one per section
};

} // namespace karity
