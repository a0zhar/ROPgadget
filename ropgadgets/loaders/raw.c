#include <stdio.h>
#include "include/raw.h"

void initRAW(RAW* raw, uint8_t* binary, size_t size, int arch, int mode, int endian) {
    raw->binary = binary;
    raw->size = size;
    raw->arch = arch;
    raw->mode = mode;
    raw->endian = endian;
}

uint64_t getEntryPointRAW() {
    return 0x0;
}

void getExecSectionsRAW(RAW* raw) {
    printf("Section Name: raw\nOffset: 0x0\nSize: %zu\nVaddr: 0x0\n", raw->size);
}

// TODO/NOTE:
// No Data Sections in raw format
void getDataSectionsRAW(RAW* raw) {}
