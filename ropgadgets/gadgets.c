#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <capstone/capstone.h>
#include "include/gadgets.h"

//
// TODO:
// Implement the passCleanX86(), gadgetsFinding() functions
// ------------------------------------------------------------
// int passCleanX86(Gadgets *g, cs_insn *decodes, size_t count);
// int gadgetsFinding(Gadgets *g, Section *section, const unsigned char *gad_op, size_t gad_size, size_t gad_align, Gadget *ret_gadgets);
// ------------------------------------------------------------
//

Gadgets *create_gadgets(unsigned char *binary, GadgetsOptions *options, unsigned long offset) {
    Gadgets *g = malloc(sizeof(Gadgets));
    g->binary = binary;
    g->options = options;
    g->offset = offset;
    g->arch = options->arch;

    char re_str[256] = "";
    if (g->arch == CS_ARCH_X86) {
        strcpy(re_str, "db|int3");
    } else if (g->arch == CS_ARCH_ARM64) {
        strcpy(re_str, "brk|smc|hvc");
    }
    if (options->filter) {
        if (strlen(re_str) > 0) {
            strcat(re_str, "|");
        }
        strcat(re_str, options->filter);
    }

    if (strlen(re_str) > 0)
        regcomp(&g->filterRE, re_str, REG_EXTENDED);


    return g;
}

static int passCleanX86(Gadgets *g, cs_insn *decodes, size_t count) {
    const char *br[] = {
        "ret", "repz ret", "retf", "int", "sysenter",
        "jmp", "notrack jmp", "call", "notrack call",
        "syscall", "iret", "iretd", "iretq", "sysret",
        "sysretq"
    };

    if (strcmp(decodes[count - 1].mnemonic, "ret") != 0)
        return 1;

    if (!g->options->multibr) {
        for (size_t i = 0; i < count - 1; i++) {
            for (size_t j = 0; j < sizeof(br) / sizeof(br[0]); j++) {
                if (strcmp(decodes[i].mnemonic, br[j]) == 0)
                    return 1;

            }
        }
    }

    for (size_t i = 0; i < count - 1; i++) {
        if (strstr(decodes[i].mnemonic, "ret") != NULL)
            return 1;

    }

    return 0;
}

static int gadgetsFinding(Gadgets *g, Section *section, const unsigned char *gad_op, size_t gad_size, size_t gad_align, Gadget *ret_gadgets) {
    const size_t PREV_BYTES = 9; // Number of bytes prior to the gadget to store.

    unsigned char *opcodes = section->opcodes;
    unsigned long sec_vaddr = section->vaddr;
    size_t gadget_count = 0;

    cs_insn *decodes;
    size_t count;

    unsigned char *found = strstr(opcodes, gad_op);
    while (found) {
        size_t ref = found - opcodes;
        size_t end = ref + gad_size;

        for (size_t i = 0; i < g->options->depth; i++) {
            size_t start = ref - (i * gad_align);
            if ((sec_vaddr + start) % gad_align == 0) {
                unsigned char *code = malloc(gad_size);
                memcpy(code, opcodes + start, gad_size);
                count = cs_disasm(g->arch, code, gad_size, sec_vaddr + start, 0, &decodes);
                if (count == 0) {
                    free(code);
                    break;
                }

                if (passCleanX86(g, decodes, count)) {
                    free(code);
                    cs_free(decodes, count);
                    break;
                }

                ret_gadgets[gadget_count].vaddr = g->offset + sec_vaddr + start;
                memcpy(ret_gadgets[gadget_count].gadget, code, gad_size);
                ret_gadgets[gadget_count].gadget_size = gad_size;

                // TODO:
                // Format the gadget string, if needed
                if (!g->options->noinstr) {}

                if (g->options->callPreceded) {
                    size_t prev_addr = sec_vaddr > ret_gadgets[gadget_count].vaddr - PREV_BYTES ? sec_vaddr : ret_gadgets[gadget_count].vaddr - PREV_BYTES;
                    memcpy(
                        ret_gadgets[gadget_count].prev,
                        opcodes + (prev_addr - sec_vaddr),
                        ret_gadgets[gadget_count].vaddr - prev_addr
                    );
                }

                // Optionally store raw bytes
                gadget_count++;

                free(code);
                cs_free(decodes, count);
            }
        }

        found = strstr(found + 1, gad_op);
    }

    return gadget_count;
}

void addROPGadgets(Gadgets *g, Section *section) {
    int arch = g->arch;
    int arch_mode = g->options->arch_mode; // Should be defined according to your architecture
    unsigned char gadgets[MAX_GADGETS][MAX_GADGET_SIZE] = { 0 };
    Gadget ret_gadgets[MAX_GADGETS] = { 0 };

    size_t gadget_count = 0;

    if (arch == CS_ARCH_X86) {
        // X86 gadgets
        gadgets[0][0] = 0xc3; // ret
        gadgets[1][0] = 0xc2; gadgets[1][1] = 0x00; gadgets[1][2] = 0x00; // ret <imm>
        gadgets[2][0] = 0xcb; // retf
        gadgets[3][0] = 0xca; gadgets[3][1] = 0x00; gadgets[3][2] = 0x00; // retf <imm>
        gadgets[4][0] = 0xf2; gadgets[4][1] = 0xc3; // ret (MPX)
        gadgets[5][0] = 0xf2; gadgets[5][1] = 0xc2; gadgets[5][2] = 0x00; gadgets[5][3] = 0x00; // ret <imm> (MPX)
        gadget_count = 6;

    } else if (arch == CS_ARCH_MIPS) {
        // MIPS gadgets (only JOP gadgets)
        // MIPS does not have RET instructions. Here we can add JOP gadgets if needed
        gadgets[0][0] = 0x03; gadgets[0][1] = 0xe0; gadgets[0][2] = 0x00; gadgets[0][3] = 0x00; // j ra
        gadgets[1][0] = 0x00; gadgets[1][1] = 0x00; gadgets[1][2] = 0x00; gadgets[1][3] = 0x00; // placeholder for additional gadgets
        gadget_count = 2;

    } else if (arch == CS_ARCH_PPC) {
        // PPC gadgets based on endianness
        if (g->options->endian == CS_MODE_BIG_ENDIAN) {
            gadgets[0][0] = 0x4e; gadgets[0][1] = 0x80; gadgets[0][2] = 0x00; gadgets[0][3] = 0x20; // blr
            gadgets[1][0] = 0x4e; gadgets[1][1] = 0x80; gadgets[1][2] = 0x00; gadgets[1][3] = 0x21; // blrl
            gadgets[2][0] = 0x4e; gadgets[2][1] = 0x80; gadgets[2][2] = 0x04; gadgets[2][3] = 0x20; // bctr
            gadgets[3][0] = 0x4e; gadgets[3][1] = 0x80; gadgets[3][2] = 0x04; gadgets[3][3] = 0x21; // bctrl
        } else {
            gadgets[0][0] = 0x20; gadgets[0][1] = 0x00; gadgets[0][2] = 0x80; gadgets[0][3] = 0x4e; // blr
            gadgets[1][0] = 0x21; gadgets[1][1] = 0x00; gadgets[1][2] = 0x80; gadgets[1][3] = 0x4e; // blrl
            gadgets[2][0] = 0x20; gadgets[2][1] = 0x04; gadgets[2][2] = 0x80; gadgets[2][3] = 0x4e; // bctr
            gadgets[3][0] = 0x21; gadgets[3][1] = 0x04; gadgets[3][2] = 0x80; gadgets[3][3] = 0x4e; // bctrl
        }
        gadget_count = 4;

    } else if (arch == CS_ARCH_SPARC) {
        // SPARC gadgets based on endianness
        if (g->options->endian == CS_MODE_BIG_ENDIAN) {
            gadgets[0][0] = 0x81; gadgets[0][1] = 0xc3; gadgets[0][2] = 0xe0; gadgets[0][3] = 0x08; // retl
            gadgets[1][0] = 0x81; gadgets[1][1] = 0xc7; gadgets[1][2] = 0xe0; gadgets[1][3] = 0x08; // ret
            gadgets[2][0] = 0x81; gadgets[2][1] = 0xe8; gadgets[2][2] = 0x00; gadgets[2][3] = 0x00; // restore
        } else {
            gadgets[0][0] = 0x08; gadgets[0][1] = 0xe0; gadgets[0][2] = 0xc3; gadgets[0][3] = 0x81; // retl
            gadgets[1][0] = 0x08; gadgets[1][1] = 0xe0; gadgets[1][2] = 0xc7; gadgets[1][3] = 0x81; // ret
            gadgets[2][0] = 0x00; gadgets[2][1] = 0x00; gadgets[2][2] = 0xe8; gadgets[2][3] = 0x81; // restore
        }
        gadget_count = 3;

    } else if (arch == CS_ARCH_ARM) {
        // ARM gadgets (only JOP gadgets)
        // ARM does not have RET instructions, but we could implement JOP gadgets if needed
        
        // placeholder for JOP gadgets
        // -----------------------------
        gadgets[0][0] = 0xe0; 
        gadgets[0][1] = 0x00; 
        gadgets[0][2] = 0x00; 
        gadgets[0][3] = 0x00;
        // -----------------------------
        gadget_count = 1;

    } else if (arch == CS_ARCH_ARM64) {
        // ARM64 gadgets based on endianness
        if (g->options->endian == CS_MODE_BIG_ENDIAN) {
            gadgets[0][0] = 0xd6; gadgets[0][1] = 0x5f; gadgets[0][2] = 0x03; gadgets[0][3] = 0xc0; // ret
        } else {
            gadgets[0][0] = 0xc0; gadgets[0][1] = 0x03; gadgets[0][2] = 0x5f; gadgets[0][3] = 0xd6; // ret
        }
        gadget_count = 1;

    } else if (arch == CS_ARCH_RISCV) {
        // RISC-V gadgets based on endianness
        if (g->options->endian == CS_MODE_BIG_ENDIAN) {
            gadgets[0][0] = 0x80; gadgets[0][1] = 0x82; // c.ret
        } else {
            gadgets[0][0] = 0x82; gadgets[0][1] = 0x80; // c.ret
        }
        gadget_count = 1;

    } else {
        fprintf(stderr, "addROPGadgets() - Architecture not supported\n");
        return;
    }

    // Find gadgets in the section
    for (size_t i = 0; i < gadget_count; i++) {
        if (gadgets[i][0] != 0) 
            // gadgetsFinding(g, 
            //   section, 
            //   gadgets[i], 
            //   /* size */, 
            //   /* alignment */, 
            //   ret_gadgets
            // );
    }

    // Process found gadgets
    for (size_t i = 0; i < gadget_count; i++) {
      // TODO:
      // Handle ret_gadgets[i] (you can log or save these gadgets as needed)
    }
}
