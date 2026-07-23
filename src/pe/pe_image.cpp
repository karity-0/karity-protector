#include "pe_image.h"

#include <cstring>
#include <fstream>
#include <stdexcept>

namespace karity {

uint32_t PeImage::align_up(uint32_t value, uint32_t alignment)
{
    if (alignment == 0) return value;
    return (value + alignment - 1) / alignment * alignment;
}

PeImage PeImage::load(const std::string &path)
{
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("karity: cannot open " + path);
    const auto size = static_cast<size_t>(f.tellg());
    f.seekg(0);
    std::vector<uint8_t> buf(size);
    f.read(reinterpret_cast<char *>(buf.data()), static_cast<std::streamsize>(size));
    if (!f) throw std::runtime_error("karity: short read on " + path);

    if (size < sizeof(IMAGE_DOS_HEADER)) throw std::runtime_error("karity: file too small for DOS header");

    PeImage img;
    std::memcpy(&img.dos_, buf.data(), sizeof(IMAGE_DOS_HEADER));
    if (img.dos_.e_magic != IMAGE_DOS_SIGNATURE) throw std::runtime_error("karity: missing MZ signature");

    const uint32_t nt_off = static_cast<uint32_t>(img.dos_.e_lfanew);
    if (nt_off < sizeof(IMAGE_DOS_HEADER) || nt_off + sizeof(IMAGE_NT_HEADERS64) > size) {
        throw std::runtime_error("karity: e_lfanew out of range");
    }
    img.dos_stub_.assign(buf.begin() + sizeof(IMAGE_DOS_HEADER), buf.begin() + nt_off);

    std::memcpy(&img.nt_, buf.data() + nt_off, sizeof(IMAGE_NT_HEADERS64));
    if (img.nt_.Signature != IMAGE_NT_SIGNATURE) throw std::runtime_error("karity: missing PE signature");
    if (img.nt_.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        throw std::runtime_error("karity: only PE64/x86-64 images are supported (skeleton limitation)");
    }
    if (img.nt_.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        throw std::runtime_error("karity: unexpected optional header magic");
    }

    // We never carry forward a trailing COFF symbol table (most PE-format
    // executables don't have one anyway; the field mostly matters for
    // object files and some debuggers). Zero it out rather than leaving a
    // stale pointer/count that points past the file we actually write.
    img.nt_.FileHeader.PointerToSymbolTable = 0;
    img.nt_.FileHeader.NumberOfSymbols = 0;

    const uint32_t sec_off = nt_off + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + img.nt_.FileHeader.SizeOfOptionalHeader;
    const uint16_t n_sections = img.nt_.FileHeader.NumberOfSections;
    if (sec_off + static_cast<uint64_t>(n_sections) * sizeof(IMAGE_SECTION_HEADER) > size) {
        throw std::runtime_error("karity: section table out of range");
    }

    img.section_headers_.resize(n_sections);
    img.section_data_.resize(n_sections);
    for (uint16_t i = 0; i < n_sections; i++) {
        IMAGE_SECTION_HEADER sh{};
        std::memcpy(&sh, buf.data() + sec_off + i * sizeof(IMAGE_SECTION_HEADER), sizeof(sh));
        img.section_headers_[i] = sh;

        if (sh.SizeOfRawData > 0) {
            if (static_cast<uint64_t>(sh.PointerToRawData) + sh.SizeOfRawData > size) {
                throw std::runtime_error("karity: section raw data out of range");
            }
            img.section_data_[i].assign(buf.begin() + sh.PointerToRawData,
                                         buf.begin() + sh.PointerToRawData + sh.SizeOfRawData);
        }
    }

    return img;
}

void PeImage::save(const std::string &path) const
{
    std::vector<uint8_t> out;
    out.reserve(1 << 20);

    out.insert(out.end(), reinterpret_cast<const uint8_t *>(&dos_),
               reinterpret_cast<const uint8_t *>(&dos_) + sizeof(dos_));
    out.insert(out.end(), dos_stub_.begin(), dos_stub_.end());

    const uint32_t nt_off = static_cast<uint32_t>(dos_.e_lfanew);
    if (out.size() != nt_off) out.resize(nt_off, 0);

    out.insert(out.end(), reinterpret_cast<const uint8_t *>(&nt_),
               reinterpret_cast<const uint8_t *>(&nt_) + sizeof(nt_));

    for (const auto &sh : section_headers_) {
        out.insert(out.end(), reinterpret_cast<const uint8_t *>(&sh),
                   reinterpret_cast<const uint8_t *>(&sh) + sizeof(sh));
    }

    for (size_t i = 0; i < section_headers_.size(); i++) {
        const auto &sh = section_headers_[i];
        if (sh.SizeOfRawData == 0) continue;
        if (out.size() < sh.PointerToRawData) out.resize(sh.PointerToRawData, 0);
        out.resize(sh.PointerToRawData);
        out.insert(out.end(), section_data_[i].begin(), section_data_[i].end());
        out.resize(sh.PointerToRawData + sh.SizeOfRawData, 0);
    }

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("karity: cannot create " + path);
    f.write(reinterpret_cast<const char *>(out.data()), static_cast<std::streamsize>(out.size()));
}

int PeImage::section_index_for_rva(uint32_t rva) const
{
    for (size_t i = 0; i < section_headers_.size(); i++) {
        const auto &sh = section_headers_[i];
        if (rva >= sh.VirtualAddress && rva < sh.VirtualAddress + std::max(sh.Misc.VirtualSize, sh.SizeOfRawData)) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

std::vector<uint8_t> PeImage::read_at_rva(uint32_t rva, size_t len) const
{
    int idx = section_index_for_rva(rva);
    if (idx < 0) throw std::runtime_error("karity: rva not within any section");
    const auto &sh = section_headers_[idx];
    const uint32_t off = rva - sh.VirtualAddress;
    if (off + len > section_data_[idx].size()) {
        throw std::runtime_error("karity: read_at_rva out of section bounds");
    }
    return std::vector<uint8_t>(section_data_[idx].begin() + off, section_data_[idx].begin() + off + len);
}

void PeImage::write_at_rva(uint32_t rva, const uint8_t *data, size_t len)
{
    int idx = section_index_for_rva(rva);
    if (idx < 0) throw std::runtime_error("karity: rva not within any section");
    const auto &sh = section_headers_[idx];
    const uint32_t off = rva - sh.VirtualAddress;
    if (off + len > section_data_[idx].size()) {
        throw std::runtime_error("karity: write_at_rva out of section bounds");
    }
    std::memcpy(section_data_[idx].data() + off, data, len);
}

uint32_t PeImage::peek_next_section_rva() const
{
    const uint32_t sect_align = nt_.OptionalHeader.SectionAlignment;
    uint32_t last_va_end = 0;
    for (const auto &sh : section_headers_) {
        last_va_end = std::max<uint32_t>(last_va_end, sh.VirtualAddress + std::max<uint32_t>(sh.Misc.VirtualSize, sh.SizeOfRawData));
    }
    return align_up(last_va_end, sect_align);
}

void PeImage::spoof_iat_directory(uint32_t rva, uint32_t size)
{
    int idx = section_index_for_rva(rva);
    if (idx < 0) throw std::runtime_error("karity: spoof_iat_directory: rva not within any section");

    if (size == 0) {
        const auto &sh = section_headers_[idx];
        const uint32_t sect_end = sh.VirtualAddress + std::max(sh.Misc.VirtualSize, sh.SizeOfRawData);
        size = sect_end - rva;
    }

    auto &dir = nt_.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    dir.VirtualAddress = rva;
    dir.Size = size;
}

std::vector<uint8_t> PeImage::read_exception_directory() const
{
    const auto &dir = nt_.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (dir.Size == 0) return {};
    return read_at_rva(dir.VirtualAddress, dir.Size);
}

void PeImage::set_exception_directory(uint32_t rva, uint32_t size)
{
    auto &dir = nt_.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    dir.VirtualAddress = rva;
    dir.Size = size;
}

uint32_t PeImage::add_section(const std::string &name, const std::vector<uint8_t> &content, uint32_t characteristics)
{
    const uint32_t file_align = nt_.OptionalHeader.FileAlignment;
    const uint32_t sect_align = nt_.OptionalHeader.SectionAlignment;

    // Header-space check: the new section header must fit before the first
    // section's on-disk data without overlapping it.
    const uint32_t nt_off = static_cast<uint32_t>(dos_.e_lfanew);
    const uint32_t sec_table_off = nt_off + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt_.FileHeader.SizeOfOptionalHeader;
    const uint32_t new_table_end = sec_table_off + (static_cast<uint32_t>(section_headers_.size()) + 1) * sizeof(IMAGE_SECTION_HEADER);
    uint32_t first_raw = nt_.OptionalHeader.SizeOfHeaders;
    for (const auto &sh : section_headers_) {
        if (sh.PointerToRawData != 0) first_raw = std::min<uint32_t>(first_raw, sh.PointerToRawData);
    }
    if (new_table_end > first_raw) {
        throw std::runtime_error("karity: no header slack to add another section (skeleton limitation)");
    }

    const uint32_t predicted_rva = peek_next_section_rva();
    uint32_t last_raw_end = 0;
    for (const auto &sh : section_headers_) {
        last_raw_end = std::max<uint32_t>(last_raw_end, sh.PointerToRawData + sh.SizeOfRawData);
    }

    IMAGE_SECTION_HEADER sh{};
    std::memset(&sh, 0, sizeof(sh));
    std::memcpy(sh.Name, name.c_str(), std::min<size_t>(name.size(), IMAGE_SIZEOF_SHORT_NAME));
    sh.VirtualAddress = predicted_rva;
    sh.Misc.VirtualSize = static_cast<uint32_t>(content.size());
    sh.SizeOfRawData = align_up(static_cast<uint32_t>(content.size()), file_align);
    sh.PointerToRawData = align_up(last_raw_end, file_align);
    sh.Characteristics = characteristics;

    std::vector<uint8_t> data = content;
    data.resize(sh.SizeOfRawData, 0);

    section_headers_.push_back(sh);
    section_data_.push_back(std::move(data));
    nt_.FileHeader.NumberOfSections = static_cast<uint16_t>(section_headers_.size());
    nt_.OptionalHeader.SizeOfImage = align_up(sh.VirtualAddress + std::max(sh.Misc.VirtualSize, sh.SizeOfRawData), sect_align);

    return sh.VirtualAddress;
}

} // namespace karity
