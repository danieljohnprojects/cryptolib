/**
 * @file MD2.c
 * @brief An implementation of the MD2 hash function. 
 * 
 * The MD2 hash takes in an arbitrarily long string of bytes and computes a 
 * 128-bit fingerprint value. We follow the description given in RFC 1319:
 * http://www.faqs.org/rfcs/rfc1319.html
 * 
 * Note that in contrast to MD4 and MD5, the MD2 hash con only be computed on 
 * strings of bytes, rather than bits.
 * 
 * This code assumes little-endianness.
 */

#include <stdio.h>
#include <Hash.h>
#include <IO.h>

#include "MD2.h"
#include "../setup.h"

/**
 * @brief Update the digest using the 16-word block from the message
 * 
 * @param message_block A block of 16 words from the message.
 * @param state_buffer A buffer to hold the internal state.
 */
void process_block(const uint8_t message_block[BLOCK_LENGTH], 
                   uint8_t state_buffer[STATE_BUFFER_LENGTH])
{
    #ifdef VERBOSE
        printf("Contents of message block:\n");
        print_bytes((uint8_t *)message_block, BLOCK_LENGTH);
    #endif

    #ifdef VERBOSE
        printf("Initial state:\n");
        print_bytes(state_buffer, STATE_BUFFER_LENGTH);
    #endif

    size_t j;
    for (j = 0; j < BLOCK_LENGTH; j++)
    {
        state_buffer[16 + j] = message_block[j];
        state_buffer[32 + j] = state_buffer[16 + j] ^ state_buffer[j];
    }

    uint8_t t = 0;

    for (j = 0; j < N_ROUNDS; j++)
    {
        for (size_t k = 0; k < STATE_BUFFER_LENGTH; k++)
        {
            state_buffer[k] = state_buffer[k] ^ PI_SUBST[t];
            t = state_buffer[k];
        }
        t = (t+j) % 256;
    }

    #ifdef VERBOSE
        printf("Final state:\n");   
        print_bytes(state_buffer, STATE_BUFFER_LENGTH);
    #endif
}

/**
 * @brief Computes the MD2 digest of a message and stores it in the given 
 * buffer. 
 * 
 * @param message A string of bytes to digest.
 * @param message_length The length in bytes of the message.
 * @param digest A buffer that will store the resulting digest.
 */
void digest(const uint8_t *message,
            size_t message_length,
            uint8_t digest_buffer[DIGEST_LENGTH])
{
    #ifdef VERBOSE
        printf("Recieved message of length %ld bytes.\n", message_length);
    #endif
    size_t buffer_length = determine_padded_length(message_length);

    #ifdef VERBOSE
        printf("Creating buffer of length %ld bytes to hold processed message.\n", buffer_length*4);
    #endif

    uint8_t processed_message[buffer_length];
    preprocess(message, message_length, processed_message, buffer_length);

    #ifdef VERBOSE
        printf("Original message:\n");
        print_bytes(message, message_length);
        printf("Processed message:\n");
        print_bytes((uint8_t *) processed_message, buffer_length*4);
    #endif

    size_t i;
    uint8_t state[STATE_BUFFER_LENGTH];
    for (i = 0; i < STATE_BUFFER_LENGTH; i++)
        state[i] = 0;
    
    size_t num_blocks = buffer_length / BLOCK_LENGTH;
    for (i = 0; i < num_blocks; i++)
    {
        #ifdef VERBOSE
            printf("Incorporating block %ld of %ld into digest\n", i, num_blocks);
        #endif
        process_block(processed_message + i*BLOCK_LENGTH, state);
    }

    for (i = 0; i < DIGEST_LENGTH; i++)
        digest_buffer[i] = state[i];
}