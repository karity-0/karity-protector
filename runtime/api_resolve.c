/*
 * runtime/api_resolve.c -- import-free WinAPI resolution (x64, Windows).
 *
 * Compiled twice, same as vm_interp.c: freestanding into the injected
 * runtime blob, and hosted for tests/test_api_resolve.c (which checks
 * results against real GetModuleHandle/GetProcAddress).
 *
 * No libc, no windows.h -- struct layouts below are hand-rolled from raw
 * offsets rather than PEB_LDR_DATA/IMAGE_EXPORT_DIRECTORY struct
 * definitions, matching the style vm_thunk.S already uses for karity_vmctx.
 * These particular offsets are undocumented but have been stable across
 * every x64 Windows release since Vista; they're what essentially all
 * position-independent shellcode loaders rely on.
 */
#include "api_resolve.h"

#define KARITY_MAX_FORWARD_DEPTH 8
#define KARITY_MAX_FORWARD_MODULE_NAME 63

static uint64_t karity_hash_step(uint64_t h, uint8_t c)
{
    if (c >= 'a' && c <= 'z') c = (uint8_t)(c - 'a' + 'A');
    return h * 33u + c;
}

uint64_t karity_hash_name(const char *ascii_name)
{
    uint64_t h = 5381;
    const char *s = ascii_name;
    while (*s) {
        h = karity_hash_step(h, (uint8_t)*s);
        s++;
    }
    return h;
}

/* Same hash, over a UTF-16 buffer with an explicit character count (PEB
 * UNICODE_STRINGs aren't NUL-terminated-guaranteed at their Length). Module
 * file names are always plain ASCII in practice, so only the low byte of
 * each UTF-16 code unit is folded in. */
static uint64_t karity_hash_name_w(const uint16_t *s, uint32_t char_count)
{
    uint64_t h = 5381;
    uint32_t i;
    for (i = 0; i < char_count; i++) {
        h = karity_hash_step(h, (uint8_t)(s[i] & 0xFF));
    }
    return h;
}

static void *karity_get_peb(void)
{
    void *peb;
    __asm__ volatile("mov %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

void *karity_resolve_module(uint64_t module_name_hash)
{
    uint8_t *peb = (uint8_t *)karity_get_peb();
    uint8_t *ldr = *(uint8_t **)(peb + 0x18);          /* PEB->Ldr */
    uint8_t *list_head = ldr + 0x20;                   /* &Ldr->InMemoryOrderModuleList */
    uint8_t *entry = *(uint8_t **)list_head;            /* first LIST_ENTRY (Flink) */

    while (entry != list_head) {
        /* `entry` points at this LDR_DATA_TABLE_ENTRY's InMemoryOrderLinks
         * field, which sits at +0x10 into the entry itself. */
        uint8_t *table_entry = entry - 0x10;
        void *dll_base = *(void **)(table_entry + 0x30);
        uint16_t name_len_bytes = *(uint16_t *)(table_entry + 0x58);       /* BaseDllName.Length */
        uint16_t *name_buf = *(uint16_t **)(table_entry + 0x58 + 8);       /* BaseDllName.Buffer */

        if (dll_base != 0 &&
            karity_hash_name_w(name_buf, name_len_bytes / 2) == module_name_hash) {
            return dll_base;
        }

        entry = *(uint8_t **)entry; /* Flink -> next entry */
    }

    return 0;
}

static void *karity_resolve_proc_depth(void *module_base, uint64_t proc_name_hash, int depth);

/* `fwd` is a NUL-terminated "ModuleName.FunctionName" forwarder string
 * living inside the exporting module's export directory (module name has
 * no extension). Resolves the target module (implicitly + ".dll") and
 * recurses into it for the function. */
static void *karity_resolve_forward(const char *fwd, int depth)
{
    char mod_name[KARITY_MAX_FORWARD_MODULE_NAME + 5]; /* + ".dll\0" */
    uint32_t i;
    const char *func_name;
    uint64_t mod_hash;
    void *target_module;

    if (depth >= KARITY_MAX_FORWARD_DEPTH) return 0;

    i = 0;
    while (fwd[i] && fwd[i] != '.' && i < KARITY_MAX_FORWARD_MODULE_NAME) {
        mod_name[i] = fwd[i];
        i++;
    }
    if (fwd[i] != '.') return 0; /* malformed forwarder string */
    mod_name[i + 0] = '.';
    mod_name[i + 1] = 'd';
    mod_name[i + 2] = 'l';
    mod_name[i + 3] = 'l';
    mod_name[i + 4] = '\0';
    func_name = fwd + i + 1;

    mod_hash = karity_hash_name(mod_name);
    target_module = karity_resolve_module(mod_hash);
    if (!target_module) return 0;

    return karity_resolve_proc_depth(target_module, karity_hash_name(func_name), depth + 1);
}

static void *karity_resolve_proc_depth(void *module_base, uint64_t proc_name_hash, int depth)
{
    uint8_t *base = (uint8_t *)module_base;
    uint32_t e_lfanew;
    uint8_t *opt_hdr;
    uint32_t export_rva, export_size;
    uint8_t *exp;
    uint32_t n_names;
    uint32_t *names;
    uint16_t *ordinals;
    uint32_t *funcs;
    uint32_t i;

    if (!base) return 0;

    e_lfanew = *(uint32_t *)(base + 0x3C);
    opt_hdr = base + e_lfanew + 0x18;    /* IMAGE_NT_HEADERS64.OptionalHeader */
    export_rva  = *(uint32_t *)(opt_hdr + 0x70);      /* DataDirectory[0].VirtualAddress */
    export_size = *(uint32_t *)(opt_hdr + 0x70 + 4);  /* DataDirectory[0].Size */
    if (export_rva == 0) return 0;

    exp = base + export_rva;
    n_names  = *(uint32_t *)(exp + 0x18);              /* NumberOfNames */
    names    = (uint32_t *)(base + *(uint32_t *)(exp + 0x20)); /* AddressOfNames */
    ordinals = (uint16_t *)(base + *(uint32_t *)(exp + 0x24)); /* AddressOfNameOrdinals */
    funcs    = (uint32_t *)(base + *(uint32_t *)(exp + 0x1C)); /* AddressOfFunctions */

    for (i = 0; i < n_names; i++) {
        const char *name = (const char *)(base + names[i]);
        if (karity_hash_name(name) == proc_name_hash) {
            uint16_t ord = ordinals[i];
            uint32_t func_rva = funcs[ord];

            if (func_rva >= export_rva && func_rva < export_rva + export_size) {
                return karity_resolve_forward((const char *)(base + func_rva), depth);
            }
            return base + func_rva;
        }
    }

    return 0;
}

void *karity_resolve_proc(void *module_base, uint64_t proc_name_hash)
{
    return karity_resolve_proc_depth(module_base, proc_name_hash, 0);
}

void *karity_resolve_api(uint64_t module_name_hash, uint64_t proc_name_hash)
{
    void *mod = karity_resolve_module(module_name_hash);
    if (!mod) return 0;
    return karity_resolve_proc(mod, proc_name_hash);
}
