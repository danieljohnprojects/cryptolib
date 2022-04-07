#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Computes the md2 digest of a message and stores it in the provided 
 * buffer. 
 * 
 * @param message A string of bytes to digest.
 * @param message_length The length in bytes of the message.
 * @param digest_buffer A buffer that will store the resulting digest.
 */
void md2digest(const uint8_t *message,
            size_t message_length,
            uint8_t *digest_buffer);

/**
 * @brief Computes the md4 digest of a message and stores it in the provided 
 * buffer. 
 * 
 * @param message A string of bytes to digest.
 * @param message_length The length in bytes of the message.
 * @param prefix_length The length of the original message not including any 
 * padding (0 unless performing a length extension attack).
 * @param digest_buffer A buffer that will store the resulting digest.
 */
void md4digest(const uint8_t *message,
            size_t message_length,
            size_t prefix_length,
            uint8_t *digest_buffer);

/**
 * @brief Computes the md5 digest of a message and stores it in the provided 
 * buffer. 
 * 
 * @param message A string of bytes to digest.
 * @param message_length The length in bytes of the message.
 * @param prefix_length The length of the original message not including any 
 * padding (0 unless performing a length extension attack).
 * @param digest_buffer A buffer that will store the resulting digest.
 */
void md5digest(const uint8_t *message,
            size_t message_length,
            size_t prefix_length,
            uint8_t *digest_buffer);

