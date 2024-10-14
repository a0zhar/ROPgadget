#include "include/rgutils.h"

// Function to delete duplicate gadgets
Gadget* delete_duplicate_gadgets(Gadget* current_gadgets, size_t* unique_count) {
    size_t current_size = *unique_count; // Get the current size of the gadgets
    Gadget* unique_gadgets = malloc(current_size * sizeof(Gadget)); // Allocate memory for unique gadgets
    if (!unique_gadgets) {
        perror("Failed to allocate memory for unique gadgets");
        exit(EXIT_FAILURE);
    }

    size_t unique_index = 0; // Index for unique gadgets
    int* gadget_found = calloc(current_size, sizeof(int)); // To track unique gadgets found
    if (!gadget_found) {
        perror("Failed to allocate memory for tracking unique gadgets");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < current_size; i++) {
        if (!gadget_found[i]) { // Check if this gadget has already been added
            strcpy(unique_gadgets[unique_index].gadget, current_gadgets[i].gadget);
            unique_index++;
            // Mark duplicates
            for (size_t j = i + 1; j < current_size; j++) {
                if (strcmp(current_gadgets[i].gadget, current_gadgets[j].gadget) == 0) {
                    gadget_found[j] = 1; // Mark as found
                }
            }
        }
    }

    free(gadget_found); // Free tracking array
    *unique_count = unique_index; // Update the unique count
    return realloc(unique_gadgets, unique_index * sizeof(Gadget)); // Resize to the actual unique count
}

// Function to sort gadgets alphabetically
void alpha_sort_gadgets(Gadget* gadgets, size_t count) {
    for (size_t i = 0; i < count - 1; i++) {
        for (size_t j = 0; j < count - i - 1; j++) {
            if (strcmp(gadgets[j].gadget, gadgets[j + 1].gadget) > 0) {
                // Swap gadgets
                Gadget temp = gadgets[j];
                gadgets[j] = gadgets[j + 1];
                gadgets[j + 1] = temp;
            }
        }
    }
}
