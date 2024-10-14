#pragma once
#ifndef _PE_HH
#define _PE_HH
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define IMAGE_SIZEOF_SHORT_NAME 8

// PEFlags constants
enum PEFlags {
    IMAGE_MACHINE_INTEL_386 = 0x014c,
    IMAGE_MACHINE_AMD_8664 = 0x8664,
    IMAGE_FILE_MACHINE_ARM = 0x1c0,
    IMAGE_FILE_MACHINE_ARMV7 = 0x1c4,
    IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
};

// Structure for IMAGE_FILE_HEADER
typedef struct {
    uint32_t Magic;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

// Structure for IMAGE_OPTIONAL_HEADER
typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
} IMAGE_OPTIONAL_HEADER;

// Structure for IMAGE_SECTION_HEADER
typedef struct {
    uint8_t Name[IMAGE_SIZEOF_SHORT_NAME];
    uint32_t PhysicalAddress;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct {
    IMAGE_FILE_HEADER fileHeader;
    IMAGE_OPTIONAL_HEADER optionalHeader;
    IMAGE_SECTION_HEADER* sections;
    uint32_t PEOffset;
    uint8_t* binary;
} PE;

int parsePE(PE* pe);
void parseSections(PE* pe);
uint64_t getEntryPoint(PE* pe);

#endif
