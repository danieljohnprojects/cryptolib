#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Computes the MD4 digest of a message and stores it in the given 
 * buffer. 
 * 
 * @param message A string of bytes to digest.
 * @param message_len The length in bytes of the message.
 * @param digest A buffer that will store the resulting digest.
 */
void MD4digest(const uint8_t *message, 
               size_t message_lenth, 
               uint8_t digest[16]);

