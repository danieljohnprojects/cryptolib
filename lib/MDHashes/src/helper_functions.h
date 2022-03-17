#pragma once

#include <stddef.h>
#include <stdint.h>

#include "constants_global.h"
#ifdef MD2
    #include "constants_MD2.h"
#endif
#ifdef MD4
    #include "constants_MD4.h"
#endif
#ifdef MD5
    #include "constants_MD5.h"
#endif

void print_digest(const uint8_t digest[DIGEST_LENGTH]);

size_t determine_padded_length(size_t message_length);

void preprocess(const uint8_t *message, 
                size_t message_length,
                uint32_t *buffer,
                size_t buffer_length);

void init_digest(uint8_t digest[DIGEST_LENGTH]);
