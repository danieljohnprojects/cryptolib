#pragma once

#include <shacal_2.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Computes the SHA1 digest of a message and stores it in the given 
 * buffer. 
 * 
 * @param message A string of bytes to digest.
 * @param message_length The length of the message measured in bytes.
 * @param prefix_length The length of the original message (0 unless performing 
 * a length extension attack).
 * @param digest_buffer A buffer that will store the resulting digest.
 */
void 
sha256digest(
    const uint8_t *message,
    size_t message_length,
    size_t prefix_length,
    block_t digest_buffer
);