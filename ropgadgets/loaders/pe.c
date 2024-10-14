#include <stdlib.h>
#include <string.h>
#include "include/pe.h"

int parsePE(PE* pe) {
    // Get the PE offset
    pe->PEOffset = *((uint32_t*)(&pe->binary[60]));
    if (memcmp(&pe->binary[pe->PEOffset], "PE\0\0", 4) != 0) {
        printf("[Error] PE::__getPEOffset() - Bad PE signature\n");
        return 0;
    }

    // Parse the PE header
    memcpy(&pe->fileHeader, &pe->binary[pe->PEOffset + 4], sizeof(IMAGE_FILE_HEADER));

    // Parse the optional header
    memcpy(&pe->optionalHeader, &pe->binary[pe->PEOffset + 24], sizeof(IMAGE_OPTIONAL_HEADER));

    // Parse sections
    parseSections(pe);
    return 1;
}

void parseSections(PE* pe) {
    uint32_t baseSections = pe->PEOffset + 24 + pe->fileHeader.SizeOfOptionalHeader;
    uint32_t sectionSize = pe->fileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    pe->sections = (IMAGE_SECTION_HEADER*)malloc(sectionSize);

    memcpy(pe->sections, &pe->binary[baseSections], sectionSize);
}

uint64_t getEntryPoint(PE* pe) {
    return pe->optionalHeader.ImageBase + pe->optionalHeader.AddressOfEntryPoint;
}
