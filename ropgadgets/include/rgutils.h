#pragma once
#ifndef _RGUTILS_HH
#define _RGUTILS_HH
#include "gadgets.h"

Gadget* delete_duplicate_gadgets(Gadget* current_gadgets, size_t* unique_count);
void alpha_sort_gadgets(Gadget* gadgets, size_t count);

#endif
