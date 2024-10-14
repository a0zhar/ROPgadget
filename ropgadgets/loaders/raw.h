#pragma once
#ifndef _RAW_HH
#define _RAW_HH
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t* binary;
    size_t size;
    int arch;
    int mode;
    int endian;
} RAW;

void initRAW(RAW* raw, uint8_t* binary, size_t size, int arch, int mode, int endian);
uint64_t getEntryPointRAW();
void getExecSectionsRAW(RAW* raw);
void getDataSectionsRAW(RAW* raw);

#endif
