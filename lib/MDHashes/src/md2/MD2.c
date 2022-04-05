/**
 * @file MD2.c
 * @brief An implementation of the MD2 hash function. 
 * 
 * The MD2 hash takes in an arbitrarily long string of bytes and computes a 
 * 128-bit fingerprint value. We follow the description given in RFC 1319:
 * http://www.faqs.org/rfcs/rfc1319.html
 * The key difference is that we do not initialise the digest buffer to the 
 * correct values. This makes it more convenient to perform length extension 
 * attacks but passes the burden of initialisation to the user when computing a 
 * regular hash.
 * 
 * Note that in contrast to MD4 and MD5, the MD2 hash con only be computed on 
 * strings of bytes, rather than bits.
 * 
 * This code assumes little-endianness.
 */

#include <stdio.h>
#include <Hash.h>
#include <IO.h>

#include "constants.h"
#include "../md.h"

// Permutation of 0..255 constructed from the digits of pi.
static uint8_t PI_SUBST[256] = {
  41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
  19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
  76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
  138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
  245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
  148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
  39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
  181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
  150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
  112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
  96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
  85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
  234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
  129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
  8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
  203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
  166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
  31, 26, 219, 153, 141, 51, 159, 17, 131, 20
};


/**
 * @brief Computes the number of bytes words needed to store a message of the 
 * given length (in bytes), plus padding and checksum.
 * 
 * @param message_length The length of the unpadded message in bytes.
 * @return The length of the corresponding buffer in bytes.
 */
static size_t determine_padded_length(size_t message_length)
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
static void preprocess(const uint8_t *message, 
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
    uint8_t L = 0;

    for (; i < message_length; i++)
    {
        buffer[i] = message[i];
        L = checksum[i % BLOCK_LENGTH] ^= PI_SUBST[L ^ message[i]];
    }

    uint8_t pad_byte = buffer_length - CHECKSUM_LENGTH - message_length;
    for (; i < buffer_length - CHECKSUM_LENGTH; i++)
    {
        buffer[i] = pad_byte;
        L = checksum[i % BLOCK_LENGTH] ^= PI_SUBST[L ^ pad_byte];
    }
}


/**
 * @brief Update the digest using the 16-word block from the message
 * 
 * @param message_block A block of 16 words from the message.
 * @param state_buffer A buffer to hold the internal state.
 */
static void process_block(const uint8_t message_block[BLOCK_LENGTH], 
                          uint8_t digest_buffer[DIGEST_LENGTH])
{
    #ifdef VERBOSE
        printf("Contents of message block:\n");
        print_bytes((uint8_t *)message_block, BLOCK_LENGTH);
    #endif

    #ifdef VERBOSE
        printf("Initial state:\n");
        print_bytes(digest_buffer, DIGEST_LENGTH);
    #endif

    uint8_t state_buffer[STATE_BUFFER_LENGTH];

    size_t j;
    for (j = 0; j < BLOCK_LENGTH; j++)
    {
        state_buffer[ 0 + j] = digest_buffer[j];
        state_buffer[16 + j] = message_block[j];
        state_buffer[32 + j] = digest_buffer[j] ^ message_block[j];
    }

    uint8_t t = 0;

    for (j = 0; j < N_ROUNDS; j++)
    {
        for (size_t k = 0; k < STATE_BUFFER_LENGTH; k++)
        {
            state_buffer[k] ^= PI_SUBST[t];
            t = state_buffer[k];
        }
        t = (t+j) % 256;
    }

    #ifdef VERBOSE
        printf("Final state:\n");   
        print_bytes(state_buffer, STATE_BUFFER_LENGTH);
    #endif

    for (j = 0; j < DIGEST_LENGTH; j++)
        digest_buffer[j] = state_buffer[j];
}


/**
 * @brief Computes the MD2 digest of a message and stores it in the given 
 * buffer. 
 * 
 * @param message A string of bytes to digest.
 * @param message_length The length in bytes of the message.
 * @param digest A buffer that will store the resulting digest.
 */
void md2digest(const uint8_t *message,
               size_t message_length,
               uint8_t digest_buffer[DIGEST_LENGTH])
{
    #ifdef VERBOSE
        printf("Recieved message of length %ld bytes.\n", message_length);
    #endif
    size_t buffer_length = determine_padded_length(message_length);

    #ifdef VERBOSE
        printf("Creating buffer of length %ld bytes to hold processed message.\n", buffer_length);
    #endif

    uint8_t processed_message[buffer_length];

    // This is where you would initialise digest_buffer to all zeros if we were doing that.

    preprocess(message, message_length, processed_message, buffer_length);

    #ifdef VERBOSE
        printf("Original message:\n");
        print_bytes(message, message_length);
        printf("Processed message:\n");
        print_bytes((uint8_t *) processed_message, buffer_length);
    #endif

    size_t i;
    
    size_t num_blocks = buffer_length / BLOCK_LENGTH;
    for (i = 0; i < num_blocks; i++)
    {
        #ifdef VERBOSE
            printf("Incorporating block %ld of %ld into digest\n", i, num_blocks);
        #endif
        process_block(processed_message + i*BLOCK_LENGTH, digest_buffer);
    }
}