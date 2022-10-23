#pragma once

#include <stdint.h>
#include <stdlib.h>

size_t determine_padded_length(size_t message_length);

void 
preprocess(
    const uint8_t *message, 
    size_t message_length,
    size_t prefix_length,
    uint32_t *buffer,
    size_t buffer_length
);