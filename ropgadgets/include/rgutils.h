#pragma once
#ifndef _RGUTILS_HH
#define _RGUTILS_HH
#include "gadgets.h"

// Adjust based on your gadget structure size
#define MAX_GADGET_SIZE 256

Gadget* delete_duplicate_gadgets(Gadget* current_gadgets, size_t* unique_count);
void alpha_sort_gadgets(Gadget* gadgets, size_t count);

#endif
