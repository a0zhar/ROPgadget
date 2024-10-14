#include "include/macho.h"

// Function to determine endianness based on magic number
int set_endianness(macho_t *macho) {
    uint32_t magic = (macho->binary[0] << 24) | (macho->binary[1] << 16) |
                     (macho->binary[2] << 8)  | (macho->binary[3]);

    if (magic == MACHO_MAGIC_32 || magic == MACHO_MAGIC_64) {
        macho->endianness = CS_MODE_BIG_ENDIAN;
        return 1; // Big-endian
    } else {
        macho->endianness = 0; // Little-endian
        return 0; // Little-endian
    }
}

// Function to parse the Mach-O header
void parse_header(macho_t *macho) {
    if (macho->endianness == CS_MODE_BIG_ENDIAN) {
        macho->header = (mach_header_t *)macho->binary;
    } else {
        macho->header = (mach_header_t *)macho->binary;
    }
}

// Function to parse load commands and sections
void parse_load_commands(macho_t *macho) {
    size_t offset = sizeof(mach_header_t);
    macho->load_cmds = (load_command_t *)&macho->binary[offset];

    for (uint32_t i = 0; i < macho->header->ncmds; ++i) {
        load_command_t *cmd = (load_command_t *)&macho->binary[offset];
        if (cmd->cmd == LC_SEGMENT) {
            segment_command_t *segment = (segment_command_t *)&macho->binary[offset];
            // Allocate space for sections and parse them
            macho->sections = realloc(macho->sections, sizeof(section_t) * segment->nsects);
            for (uint32_t j = 0; j < segment->nsects; ++j) {
                section_t *section = (section_t *)&macho->binary[offset + sizeof(segment_command_t) + (j * sizeof(section_t))];
                macho->sections[j] = *section; // Copy section data
                // Adjust offset as needed
            }
            macho->section_count += segment->nsects;
        }
        offset += cmd->cmdsize; // Move to the next command
    }
}

// Function to get the entry point
uint32_t get_entry_point(macho_t *macho) {
    for (size_t i = 0; i < macho->section_count; ++i) {
        if (strncmp(macho->sections[i].sectname, "__text", 6) == 0) 
            return macho->sections[i].addr;
    }
    return 0; // Entry point not found
}

// Function to free resources
void free_macho(macho_t *macho) {
    free(macho->sections);
    free(macho->load_cmds);
    free(macho);
}
