#pragma once
#ifndef _GADGETS_HH
#define _GADGETS_HH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <capstone/capstone.h>

// Maximum number of gadgets and size of each gadget
#define MAX_GADGETS 1024
#define MAX_GADGET_SIZE 16

// Options for gadget generation
typedef struct {
    unsigned char *binary;  // Binary data
    int arch;               // Architecture (e.g., x86, ARM)
    int depth;              // Depth for gadget finding
    int align;              // Alignment for gadgets
    int noinstr;            // No instruction option
    int callPreceded;       // Option for preceding call
    char *filter;           // Regex filter for gadgets
    unsigned int offset;    // Offset for gadgets
} GadgetsOptions;

// Structure for sections of binary
typedef struct {
    unsigned char *opcodes; // Opcode data of the section
    unsigned long vaddr;    // Virtual address of the section
} Section;

// Structure representing a single gadget
typedef struct {
    unsigned long vaddr;                   // Virtual address of the gadget
    unsigned char gadget[MAX_GADGET_SIZE]; // Gadget bytes
    size_t gadget_size;                    // Size of the gadget
    unsigned char prev[MAX_GADGET_SIZE];   // Previous instruction bytes
    size_t prev_size;                      // Size of previous bytes
    unsigned char bytes[MAX_GADGET_SIZE];  // Raw bytes of the gadget
    size_t bytes_size;                     // Size of raw bytes
} Gadget;

// Structure for managing gadgets
typedef struct {
    unsigned char *binary;     // Binary data
    GadgetsOptions *options;   // Options for gadget finding
    unsigned long offset;      // Offset for gadget finding
    int arch;                  // Architecture
    regex_t filterRE;          // Regex for filtering gadgets
} Gadgets;


Gadgets *create_gadgets(unsigned char *binary, GadgetsOptions *options, unsigned long offset);
int passCleanX86(Gadgets *g, cs_insn *decodes, size_t count);
int gadgetsFinding(Gadgets *g, Section *section, const unsigned char *gad_op, size_t gad_size, size_t gad_align, Gadget *ret_gadgets);
void addROPGadgets(Gadgets *g, Section *section);

#endif
