#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/elf.h"

ELF *elf_parse(const uint8_t *binary, size_t size) {
    if (size < sizeof(Elf64_Ehdr)) return NULL;

    ELF *elf = malloc(sizeof(ELF));
    if (!elf) return NULL;

    elf->binary = malloc(size);
    if (!elf->binary) {
        free(elf);
        return NULL;
    }
    memcpy(elf->binary, binary, size);
    elf->binary_size = size;

    memcpy(&elf->header, binary, sizeof(Elf64_Ehdr));
    elf->phdr_count = elf->header.e_phnum;
    elf->shdr_count = elf->header.e_shnum;

    // Allocate memory for program headers
    elf->phdrs = malloc(elf->phdr_count * sizeof(Elf64_Phdr));
    memcpy(elf->phdrs, binary + elf->header.e_phoff, elf->phdr_count * sizeof(Elf64_Phdr));

    // Allocate memory for section headers
    elf->shdrs = malloc(elf->shdr_count * sizeof(Elf64_Shdr));
    memcpy(elf->shdrs, binary + elf->header.e_shoff, elf->shdr_count * sizeof(Elf64_Shdr));

    return elf;
}

void elf_free(ELF *elf) {
    if (elf) {
        free(elf->phdrs);
        free(elf->shdrs);
        free(elf->binary);
        free(elf);
    }
}

void elf_print_info(const ELF *elf) {
    printf("ELF Header:\n");
    printf("  Entry point: 0x%lx\n", elf->header.e_entry);
    printf("  Program headers: %zu\n", elf->phdr_count);
    printf("  Section headers: %zu\n", elf->shdr_count);
}
