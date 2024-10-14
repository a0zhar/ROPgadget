#pragma once
#ifndef _GADGETS_HPP
#define _GADGETS_HPP

#include <regex>
#include <string>
#include <vector>

class Gadgets {
public:
    Gadgets(Binary* binary, Options* options, uint64_t offset);
    
    std::vector<Gadget> addROPGadgets(Section section);
    std::vector<Gadget> addJOPGadgets(Section section);

private:
    struct Gadget {
        uint64_t vaddr;
        std::string gadget;
        std::string prev;
        std::vector<uint8_t> bytes;
    };

    Binary* binary;
    Options* options;
    uint64_t offset;
    int arch;

    std::regex filterRE;
    bool passCleanX86(const std::vector<Instruction>& decodes);
    std::vector<Gadget> gadgetsFinding(const Section& section, const std::vector<GadgetPattern>& gadgets, int arch, int mode);

    // Nested structs to handle gadgets pattern
    struct GadgetPattern {
        std::string pattern;
        size_t size;
        size_t alignment;
    };
};

#endif
