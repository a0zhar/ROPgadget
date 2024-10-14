#pragma once
#ifndef _MACHO_HH
#define _MACHO_HH
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define CS_MODE_BIG_ENDIAN 1
#define CS_MODE_32 0
#define CS_MODE_64 1

#define MACHO_MAGIC_32 0xfeedface
#define MACHO_MAGIC_64 0xfeedfacf

#define MACHO_CPU_TYPE_I386 0x7
#define MACHO_CPU_TYPE_X86_64 (MACHO_CPU_TYPE_I386 | 0x1000000)
#define MACHO_CPU_TYPE_ARM 12
#define MACHO_CPU_TYPE_ARM64 (MACHO_CPU_TYPE_ARM | 0x1000000)
#define MACHO_CPU_TYPE_MIPS 0x8
#define MACHO_CPU_TYPE_POWERPC 18
#define MACHO_CPU_TYPE_POWERPC64 (MACHO_CPU_TYPE_POWERPC | 0x1000000)

#define LC_SEGMENT 0x1
#define LC_SEGMENT_64 0x19

#define S_ATTR_SOME_INSTRUCTIONS 0x00000400
#define S_ATTR_PURE_INSTRUCTIONS 0x80000000

typedef struct __attribute__((__packed__)) {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
} mach_header_t;

typedef struct __attribute__((__packed__)) {
    uint32_t cmd;
    uint32_t cmdsize;
} load_command_t;

typedef struct __attribute__((__packed__)) {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
} segment_command_t;

typedef struct __attribute__((__packed__)) {
    char sectname[16];
    char segname[16];
    uint32_t addr;
    uint32_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
} section_t;

typedef struct {
    uint8_t *binary;
    size_t size;
    mach_header_t *header;
    int endianness;
    load_command_t *load_cmds;
    section_t *sections;
    size_t section_count;
} macho_t;

int set_endianness(macho_t *macho);
void parse_header(macho_t *macho);
void parse_load_commands(macho_t *macho);
uint32_t get_entry_point(macho_t *macho);
void free_macho(macho_t *macho);

#endif
