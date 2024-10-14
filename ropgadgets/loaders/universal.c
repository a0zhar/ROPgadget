#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/universal.h"

UNIVERSAL *universal_parse(const uint8_t *binary, size_t size) {
    if (size < sizeof(FAT_HEADER)) return NULL;

    UNIVERSAL *univ = malloc(sizeof(UNIVERSAL));
    if (!univ) return NULL;

    memcpy(&univ->fat_header, binary, sizeof(FAT_HEADER));
    univ->binary_count = univ->fat_header.nfat_arch;
    univ->binaries = malloc(univ->binary_count * sizeof(ELF *));
    
    size_t offset = sizeof(FAT_HEADER);
    for (uint32_t i = 0; i < univ->binary_count; ++i) {
        FAT_ARCH arch;
        memcpy(&arch, binary + offset, sizeof(FAT_ARCH));
        univ->binaries[i] = elf_parse(binary + arch.offset, arch.size);
        if (!univ->binaries[i]) {
            // Handle error
            break;
        }
        offset += sizeof(FAT_ARCH);
    }

    return univ;
}

void universal_free(UNIVERSAL *univ) {
    if (univ) {
        for (size_t i = 0; i < univ->binary_count; ++i) {
            elf_free(univ->binaries[i]);
        }
        free(univ->binaries);
        free(univ);
    }
}

void universal_print_info(const UNIVERSAL *univ) {
    printf("Universal Binary Info:\n");
    for (size_t i = 0; i < univ->binary_count; ++i) {
        printf("Binary %zu:\n", i);
        elf_print_info(univ->binaries[i]);
    }
}
