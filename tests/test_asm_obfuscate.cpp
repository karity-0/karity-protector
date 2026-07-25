// Unit test for obfuscate_asm (src/native/asm_obfuscate.cpp): junk `.byte`
// runs must be spliced only between instructions inside executable (.text)
// sections, never into data sections, and the original source text must be
// preserved verbatim around them.

#include <cstdio>
#include <random>
#include <string>

#include "asm_obfuscate.h"

using karity::obfuscate_asm;

static int failures = 0;
#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        if (!(cond)) {                                                          \
            std::printf("FAIL: %s\n", msg);                                     \
            failures++;                                                         \
        }                                                                       \
    } while (0)

int main()
{
    // .text has real instructions; .rodata carries an instruction-*looking*
    // line ("nop") that must NOT get junk after it because we're not in .text.
    const std::string input =
        "\t.text\n"
        "main:\n"
        "\tmovl $1, %eax\n"
        "\taddl $2, %eax\n"
        "\tret\n"
        "\t.section .rodata\n"
        "notreally:\n"
        "\tnop\n"
        "\t.text\n"
        "\tmovl $3, %ecx\n";

    std::mt19937_64 rng(12345);
    // density 1.0 forces a junk blob after every eligible (in-.text) instruction.
    std::string out = obfuscate_asm(input, rng, 1.0);

    // (a) junk actually inserted somewhere.
    CHECK(out.find(".byte") != std::string::npos, "no .byte junk inserted at all");

    // (b) original mnemonics preserved verbatim.
    CHECK(out.find("movl $1, %eax") != std::string::npos, "lost first instruction");
    CHECK(out.find("addl $2, %eax") != std::string::npos, "lost second instruction");
    CHECK(out.find("movl $3, %ecx") != std::string::npos, "lost post-rodata instruction");

    // (c) no junk landed inside the .rodata region (between ".section .rodata"
    // and the following ".text"). The "nop" there must survive junk-free.
    size_t rodata = out.find(".section .rodata");
    CHECK(rodata != std::string::npos, "rodata section vanished");
    size_t back_to_text = out.find("\t.text", rodata + 1);
    CHECK(back_to_text != std::string::npos, "second .text vanished");
    if (rodata != std::string::npos && back_to_text != std::string::npos) {
        std::string data_region = out.substr(rodata, back_to_text - rodata);
        CHECK(data_region.find(".byte") == std::string::npos,
              "junk .byte leaked into .rodata data section");
        CHECK(data_region.find("nop") != std::string::npos, "lost the rodata nop line");
    }

    // (d) density 0 inserts nothing.
    std::mt19937_64 rng2(777);
    std::string none = obfuscate_asm(input, rng2, 0.0);
    CHECK(none.find(".byte") == std::string::npos, "density 0 still inserted junk");
    CHECK(none == input, "density 0 changed the source (should round-trip verbatim)");

    if (failures == 0) {
        std::printf("test_asm_obfuscate: all checks passed\n");
        return 0;
    }
    std::printf("test_asm_obfuscate: %d failure(s)\n", failures);
    return 1;
}
