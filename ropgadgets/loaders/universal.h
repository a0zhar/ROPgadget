#pragma once
#ifndef _UNIVERSAL_HH
#define _UNIVERSAL_HH

#include <stdint.h>
#include "elf.h"

typedef struct {
    uint32_t magic;
    uint32_t nfat_arch;
} FAT_HEADER;

typedef struct {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
} FAT_ARCH;

typedef struct {
    FAT_HEADER fat_header;
    ELF **binaries;
    size_t binary_count;
} UNIVERSAL;

UNIVERSAL *universal_parse(const uint8_t *binary, size_t size);
void universal_free(UNIVERSAL *univ);
void universal_print_info(const UNIVERSAL *univ);

#endif
