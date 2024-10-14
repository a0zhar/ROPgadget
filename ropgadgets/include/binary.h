#pragma once
#ifndef _BINARY_HH
#define _BINARY_HH
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../loaders/include/elf.h"
#include "../loaders/include/macho.h"
#include "../loaders/include/pe.h"
#include "../loaders/include/raw.h"
#include "../loaders/include/universal.h"

typedef struct {
    char *file_name;
    uint8_t *raw_binary;  // Raw binary data
    void *binary;         // Pointer to the specific binary format structure
} Binary;

Binary* create_binary(const char *filename, const char *raw_arch, int thumb, const char *raw_mode, const char *raw_endian);

#endif
