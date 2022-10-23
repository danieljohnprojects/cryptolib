/**
 * @file preprocessing.c
 * @author Daniel John (daniel.john.projects@gmail.com)
 * @brief Code for message preprocessing in SHA-1 and SHA-256
 * @version 0.1
 * @date 2022-10-23
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <stdint.h>
#include <stdlib.h>

#define BYTES_PER_WORD 4

// Padding is added to a message so that its length in bytes is congruent to 
// PAD_REMAINDER modulo PAD_BLOCK.
#define PAD_BLOCK 64
#define PAD_REMAINDER 56

// Reverse the endianness of a uint32
#define MIRROR32(x) ((((x)&0xff) << 24) | (((x)&0xff00) << 8) | (((x)&0xff0000) >> 8) | (((x)&0xff000000) >> 24))

/**
 * @brief Computes the number of 32-bit words needed to store a message of the 
 * given length (in bytes), plus padding and the representation of the message 
 * length.
 * 
 * @param message_length The length of the unpadded message in bytes.
 * @return The length of the corresponding buffer in words.
 */
size_t determine_padded_length(size_t message_length) {
    size_t x80_padding_length = 1;
    size_t zero_padding_length = ((PAD_REMAINDER - (message_length + x80_padding_length)) % PAD_BLOCK);
    size_t length_length = PAD_BLOCK - PAD_REMAINDER;
    size_t byte_length = message_length + x80_padding_length + zero_padding_length + length_length;

    return byte_length / BYTES_PER_WORD;
}

/**
 * Fills a buffer with the given message and the appropriate padding.
 * 
 * This should be the only part of the code that needs to account for endianness 
 * since we are converting from bytes to ints. We want the first byte of the 
 * message to be the most significant byte of the first word. Since we are working 
 * on a little endian machine we need to reverse the byte order for each word.
 * 
 * @param message A pointer to an array of bytes constituting the message. Note 
 * that this is not necessarily a string so does not need a null terminator.
 * @param message_length The length of the message in bytes.
 * @param prefix_length The length of the original message  not including any 
 * padding (0 unless performing a length extension attack).
 * @param buffer A pointer to an array that will store the processed message.
 * @param buffer_length The length of the buffer in 32-bit words.
 */
void 
preprocess(
    const uint8_t *message, 
    size_t message_length,
    size_t prefix_length,
    uint32_t *buffer,
    size_t buffer_length
) {
    for (size_t i = 0; i < buffer_length; i++)
        buffer[i] = 0UL;

    uint8_t *byte_buffer;
    byte_buffer = (uint8_t *) buffer;

    // Copy over the message, one byte at a time.
    size_t i = 0;
    for (; i < message_length; i++) {
        byte_buffer[i] = message[i];
    }
    // Add a single bit at the end.
    byte_buffer[i] = 0x80;
    i++;

    // The first byte of the message needs to be the most significant byte of the first word.
    // Since we are working on a little endian machine we need to reverse the endianness of each word.
    for (size_t j = 0; j < (i + BYTES_PER_WORD - 1) / BYTES_PER_WORD; j++) {
        buffer[j] = MIRROR32(buffer[j]);
    }

    // Store the bit-length of the message at the end of the buffer.
    if (prefix_length)
        prefix_length = BYTES_PER_WORD*determine_padded_length(prefix_length);
    // Need message_length in *bits*
    message_length = (message_length + prefix_length) * 8;
    buffer[buffer_length - 1] = message_length & 0xffffffff;
    buffer[buffer_length - 2] = (message_length & 0xffffffff00000000) >> 32;
}
