#include "include/binary.h"

//
// TODO:
// Implement the functions:
// const char* get_file_name(Binary *binary);
// uint8_t* get_raw_binary(Binary *binary);
// void* get_binary(Binary *binary);
// uintptr_t get_entry_point(Binary *binary);
// void* get_data_sections(Binary *binary);
// void* get_exec_sections(Binary *binary);
// const char* get_arch(Binary *binary);
// const char* get_arch_mode(Binary *binary);
// const char* get_endian(Binary *binary);
// const char* get_format(Binary *binary);
// void free_binary(Binary *binary);
//

Binary* create_binary(const char *filename, const char *raw_arch, int thumb, const char *raw_mode, const char *raw_endian) {
    Binary *binary = malloc(sizeof(Binary));
    if (!binary) {
        perror("[Error] Memory allocation failed");
        return NULL;
    }

    binary->file_name = strdup(filename);
    if (!binary->file_name) {
        perror("[Error] Memory allocation failed for file name");
        free(binary);
        return NULL;
    }

    // Read the binary file
    FILE *fd = fopen(filename, "rb");
    if (!fd) {
        perror("[Error] Can't open the binary or binary not found");
        free(binary->file_name);
        free(binary);
        return NULL;
    }

    fseek(fd, 0, SEEK_END);
    long file_size = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    binary->raw_binary = malloc(file_size);
    if (!binary->raw_binary) {
        perror("[Error] Memory allocation failed for raw binary");
        fclose(fd);
        free(binary->file_name);
        free(binary);
        return NULL;
    }

    fread(binary->raw_binary, 1, file_size, fd);
    fclose(fd);

    // Determine the binary format and create the appropriate structure
    if (raw_arch) {
        // Assume Raw is a function defined in raw.h
        binary->binary = create_raw(binary->raw_binary, raw_arch, thumb ? "thumb" : raw_mode, raw_endian);
    } else if (memcmp(binary->raw_binary, "\x7f""ELF", 4) == 0) {
        binary->binary = create_elf(binary->raw_binary);
    } else if (memcmp(binary->raw_binary, "MZ", 2) == 0) {
        binary->binary = create_pe(binary->raw_binary);
    } else if (memcmp(binary->raw_binary, "\xca\xfe\xba\xbe", 4) == 0) {
        binary->binary = create_universal(binary->raw_binary);
    } else if (memcmp(binary->raw_binary, "\xce\xfa\xed\xfe", 4) == 0 ||
               memcmp(binary->raw_binary, "\xcfa\xed\xfe", 4) == 0 ||
               memcmp(binary->raw_binary, "\xfe\xed\xfa\xce", 4) == 0 ||
               memcmp(binary->raw_binary, "\xfe\xed\xfa\xcf", 4) == 0) {
        binary->binary = create_macho(binary->raw_binary);
    } else {
        fprintf(stderr, "[Error] Binary format not supported\n");
        free(binary->raw_binary);
        free(binary->file_name);
        free(binary);
        return NULL;
    }

    return binary;
}
