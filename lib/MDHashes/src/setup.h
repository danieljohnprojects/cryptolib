#pragma once

#include <stddef.h>
#include <stdint.h>

size_t determine_padded_length(size_t message_length);

void init_digest(uint8_t *digest);
