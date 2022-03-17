#pragma once

#include <MD4.h>
#include <stddef.h>
#include <stdint.h>

#include "constants.h"

size_t determine_padded_length(size_t message_length);

void preprocess(const uint8_t *message, 
                size_t message_length,
                uint32_t *buffer,
                size_t buffer_length);

void init_digest(uint8_t digest[DIGEST_LENGTH]);

void process_block(const uint32_t message_block[WORDS_PER_BLOCK], 
                   uint8_t digest[DIGEST_LENGTH]);

void print_digest(const uint8_t digest[DIGEST_LENGTH]);