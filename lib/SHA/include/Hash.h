#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Computes the sha1 digest of a message and stores it in the provided 
 * buffer. 
 * 
 * @param message A string of bytes to digest.
 * @param message_length The length in bytes of the message.
 * @param digest_buffer A buffer that will store the resulting digest.
 */
void sha1digest(const uint8_t *message,
            size_t message_length,
            uint8_t *digest_buffer);