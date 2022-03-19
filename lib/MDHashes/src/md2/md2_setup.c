#include <IO.h>
#include <stdint.h>
#include <stdio.h>

#include "../setup.h"
#include "MD2.h"


/**
 * @brief Computes the number of bytes words needed to store a message of the 
 * given length (in bytes), plus padding and checksum.
 * 
 * @param message_length The length of the unpadded message in bytes.
 * @return The length of the corresponding buffer in bytes.
 */
size_t determine_padded_length(size_t message_length)
{
    size_t padding_length = BLOCK_LENGTH - (message_length % BLOCK_LENGTH);
    return message_length + padding_length + CHECKSUM_LENGTH;
}

/**
 * Fills a buffer with the given message, appropriately padded and with 
 * checksum appended.
 * 
 * @param message A pointer to an array of bytes constituting the message. Note 
 * that this is not necesarilly a string so does not need a null terminator.
 * @param message_length The length of the message in bytes.
 * @param buffer A pointer to an array that will store the processed 
 * message.
 * @param buffer_length The length of the buffer in bytes.
 */
void preprocess(const uint8_t *message, 
                size_t message_length,
                uint8_t *buffer,
                size_t buffer_length)
{
    // Initialise the checksum
    uint8_t *checksum = buffer + buffer_length - CHECKSUM_LENGTH;
    size_t i = 0;
    for (; i < CHECKSUM_LENGTH; i++)
        checksum[i] = 0;
    
    i = 0;
    uint8_t j = 0;
    uint8_t L = 0;

    for (; i < message_length; i++, j=(j+1)%16)
    {
        buffer[i] = message[i];
        checksum[j] = PI_SUBST[L ^ message[i]];
        L = checksum[j];
    }

    uint8_t pad_byte = buffer_length - CHECKSUM_LENGTH - message_length;
    for (; i < buffer_length - CHECKSUM_LENGTH; i++, j=(j+1)%16)
    {
        buffer[i] = pad_byte;
        checksum[j] = PI_SUBST[L ^ pad_byte];
        L = checksum[j];
    }
}
