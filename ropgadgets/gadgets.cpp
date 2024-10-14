//
// UNFINISHED REWRITE OF gadgets.py !!!
//

#include <capstone/capstone.h>
#include <iostream>
#include <regex>
#include <sstream>
#include <cstring>
#include "gadgets.hpp"

Gadgets::Gadgets(Binary *binary, Options *options, uint64_t offset)
    : binary(binary), options(options), offset(offset) {
    arch = binary->getArch();

    std::string re_str;
    if (arch == CS_ARCH_X86) {
        re_str = "db|int3";
    } else if (arch == CS_ARCH_ARM64) {
        re_str = "brk|smc|hvc";
    }

    if (!options->filter.empty()) {
        if (!re_str.empty()) {
            re_str += "|";
        }
        re_str += options->filter;
    }

    if (!re_str.empty()) 
      filterRE = std::regex("(" + re_str + ")$");
    
}

bool Gadgets::passCleanX86(const std::vector<Instruction> &decodes) {
    std::vector<std::string> br = { 
        "ret", "repz ret", "retf", 
        "int", "sysenter", "jmp", 
        "notrack jmp", "call", "notrack call", 
        "syscall", "iret", "iretd", 
        "iretq", "sysret", "sysretq" 
    };

    if (std::find(br.begin(), br.end(), decodes.back().mnemonic) == br.end()) 
        return true;
    

    if (!options->multibr) {
        for (size_t i = 0; i < decodes.size() - 1; ++i) {
            if (std::find(br.begin(), br.end(), decodes[i].mnemonic) != br.end()) 
                return true;
            
        }
    }

    for (size_t i = 0; i < decodes.size() - 1; ++i) {
        if (decodes[i].mnemonic.find("ret") != std::string::npos) 
            return true;
        
    }

    return false;
}

std::vector<Gadgets::Gadget> Gadgets::gadgetsFinding(const Section &section, const std::vector<GadgetPattern> &gadgets, int arch, int mode) {
    const size_t PREV_BYTES = 9;

    std::vector<Gadget> ret;
    const std::vector<uint8_t> &opcodes = section.opcodes;
    uint64_t sec_vaddr = section.vaddr;

    csh handle;
    cs_open((cs_arch)arch, (cs_mode)mode, &handle);

    for (const auto &gad : gadgets) {
        std::string gad_op = gad.pattern;
        size_t gad_size = gad.size;
        size_t gad_align = gad.alignment;

        if (options->align > 0) gad_align = options->align;

        std::regex regex(gad_op);
        auto matches_begin = std::sregex_iterator(opcodes.begin(), opcodes.end(), regex);
        auto matches_end = std::sregex_iterator();

        for (std::sregex_iterator i = matches_begin; i != matches_end; ++i) {
            std::smatch match = *i;
            size_t ref = match.position();
            size_t end = ref + gad_size;

            for (size_t depth = 0; depth < options->depth; ++depth) {
                size_t start = ref - (depth * gad_align);
                if ((sec_vaddr + start) % gad_align != 0)
                    continue;


                const uint8_t *code_ptr = &opcodes[start];
                cs_insn *insn;
                size_t count = cs_disasm(
                    handle,
                    code_ptr,
                    end - start,
                    sec_vaddr + start,
                    0,
                    &insn
                );

                if (count == 0) continue;


                std::vector<Instruction> decodes;
                for (size_t i = 0; i < count; ++i) {
                    decodes.push_back({
                      insn[i].address,
                      insn[i].size,
                      insn[i].mnemonic,
                      insn[i].op_str
                    });
                }
                cs_free(insn, count);

                if (passCleanX86(decodes)) 
                  continue;
                

                uint64_t vaddr = offset + sec_vaddr + start;
                Gadget g = { vaddr };

                if (!options->noinstr) {
                    std::stringstream ss;
                    for (const auto &decode : decodes) {
                        ss << decode.mnemonic << " " << decode.op_str << " ; ";
                    }
                    g.gadget = ss.str();
                }

                if (options->callPreceded) {
                    size_t prevBytesAddr = std::max(sec_vaddr, vaddr - PREV_BYTES);
                    g.prev = std::string(
                        opcodes.begin() + (prevBytesAddr - sec_vaddr),
                        opcodes.begin() + (vaddr - sec_vaddr)
                    );
                }

                if (options->dump) {
                    g.bytes.assign(opcodes.begin() + start, opcodes.begin() + end);
                }

                ret.push_back(g);
            }
        }
    }

    cs_close(&handle);
    return ret;
}

std::vector<Gadgets::Gadget> Gadgets::addROPGadgets(Section section) {
    int arch = binary->getArch();
    int arch_mode = binary->getArchMode();
    int arch_endian = binary->getEndian();

    std::vector<GadgetPattern> gadgets;

    if (arch == CS_ARCH_X86) {
        gadgets = {
            {"\xc3", 1, 1},                 // ret
            {"\xc2[\\x00-\\xff]{2}", 3, 1}, // ret <imm>
            {"\xcb", 1, 1},                 // retf
            {"\xca[\\x00-\\xff]{2}", 3, 1}  // retf <imm>
        };
    } else if (arch == CS_ARCH_ARM64) {
        if (arch_endian == CS_MODE_BIG_ENDIAN) {
            gadgets = { {"\xd6\x5f\x03\xc0", 4, 4} };  // ret
        } else {
            gadgets = { {"\xc0\x03\x5f\xd6", 4, 4} };  // ret
        }
        arch_mode = CS_MODE_ARM;
    }
    // TODO:
    // Other architectures to be handled similarly...

    if (!gadgets.empty()) {
        return gadgetsFinding(section, gadgets, arch, arch_mode + arch_endian);
    }

    return {};
}
