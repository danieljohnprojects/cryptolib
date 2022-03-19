/**
 * @file MD4.c
 * @brief An implementation of the MD4 hash function. 
 * 
 * The MD4 hash takes in an arbitrary length message and computes a 128-bit 
 * value. We follow the description given in RFC 1320:
 * http://www.faqs.org/rfcs/rfc1320.html
 * Except that we will always assume that messages are strings of bytes, rather
 * than of bits.
 * 
 * This code assumes little-endianness.
 */

#include <stdio.h>
#include <Hash.h>
#include <IO.h>

#include "MD4.h"
#include "../setup.h"


/**
 * @brief Update the digest using the 16-word block from the message
 * 
 * @param message_block A block of 16 words from the message.
 * @param digest The digest of the hash
 */
void process_block(const uint32_t message_block[WORDS_PER_BLOCK], 
                   uint8_t digest_buffer[DIGEST_LENGTH])
{
    #ifdef VERBOSE
        printf("Contents of message block:\n");
        print_bytes((uint8_t *)message_block, WORDS_PER_BLOCK*4);
    #endif

    uint32_t *A = ((uint32_t *)digest_buffer) +  0;
    uint32_t *B = ((uint32_t *)digest_buffer) +  1;
    uint32_t *C = ((uint32_t *)digest_buffer) +  2;
    uint32_t *D = ((uint32_t *)digest_buffer) +  3;

    uint32_t a = *A;
    uint32_t b = *B;
    uint32_t c = *C;
    uint32_t d = *D;

    #ifdef VERBOSE
        printf("Initial digest state:\n");
        print_bytes(digest_buffer, DIGEST_LENGTH);
    #endif

    // Round 1
    FF(a, b, c, d, message_block[ 0], S11);
    FF(d, a, b, c, message_block[ 1], S12);
    FF(c, d, a, b, message_block[ 2], S13);
    FF(b, c, d, a, message_block[ 3], S14);
    FF(a, b, c, d, message_block[ 4], S11);
    FF(d, a, b, c, message_block[ 5], S12);
    FF(c, d, a, b, message_block[ 6], S13);
    FF(b, c, d, a, message_block[ 7], S14);
    FF(a, b, c, d, message_block[ 8], S11);
    FF(d, a, b, c, message_block[ 9], S12);
    FF(c, d, a, b, message_block[10], S13);
    FF(b, c, d, a, message_block[11], S14);
    FF(a, b, c, d, message_block[12], S11);
    FF(d, a, b, c, message_block[13], S12);
    FF(c, d, a, b, message_block[14], S13);
    FF(b, c, d, a, message_block[15], S14);
    // Round 2
    GG(a, b, c, d, message_block[ 0], S21);
    GG(d, a, b, c, message_block[ 4], S22);
    GG(c, d, a, b, message_block[ 8], S23);
    GG(b, c, d, a, message_block[12], S24);
    GG(a, b, c, d, message_block[ 1], S21);
    GG(d, a, b, c, message_block[ 5], S22);
    GG(c, d, a, b, message_block[ 9], S23);
    GG(b, c, d, a, message_block[13], S24);
    GG(a, b, c, d, message_block[ 2], S21);
    GG(d, a, b, c, message_block[ 6], S22);
    GG(c, d, a, b, message_block[10], S23);
    GG(b, c, d, a, message_block[14], S24);
    GG(a, b, c, d, message_block[ 3], S21);
    GG(d, a, b, c, message_block[ 7], S22);
    GG(c, d, a, b, message_block[11], S23);
    GG(b, c, d, a, message_block[15], S24);
    // Round 3
    HH(a, b, c, d, message_block[ 0], S31);
    HH(d, a, b, c, message_block[ 8], S32);
    HH(c, d, a, b, message_block[ 4], S33);
    HH(b, c, d, a, message_block[12], S34);
    HH(a, b, c, d, message_block[ 2], S31);
    HH(d, a, b, c, message_block[10], S32);
    HH(c, d, a, b, message_block[ 6], S33);
    HH(b, c, d, a, message_block[14], S34);
    HH(a, b, c, d, message_block[ 1], S31);
    HH(d, a, b, c, message_block[ 9], S32);
    HH(c, d, a, b, message_block[ 5], S33);
    HH(b, c, d, a, message_block[13], S34);
    HH(a, b, c, d, message_block[ 3], S31);
    HH(d, a, b, c, message_block[11], S32);
    HH(c, d, a, b, message_block[ 7], S33);
    HH(b, c, d, a, message_block[15], S34);

    *A += a;
    *B += b;
    *C += c;
    *D += d;

    #ifdef VERBOSE
        printf("Final digest state:\n");   
        print_bytes(digest_buffer, DIGEST_LENGTH);
    #endif
}


/**
 * @brief Computes the MD4 digest of a message and stores it in the given 
 * buffer. 
 * 
 * @param message A string of bytes to digest.
 * @param message_length The length in bytes of the message.
 * @param digest_buffer A buffer that will store the resulting digest.
 */
void md4digest(const uint8_t *message, 
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
    uint32_t processed_message[buffer_length];

    preprocess(message, message_length, processed_message, buffer_length);
    #ifdef VERBOSE
        printf("Original message:\n");
        print_bytes(message, message_length);
        // for (size_t i = 0; i < message_length; i++)
        //     printf("%02x", message[i]);
        // printf("\n");
        printf("Processed message:\n");
        print_bytes((uint8_t *) processed_message, buffer_length*4);
        // for (size_t i = 0; i < buffer_length*4; i++)
        // {
        //     if (i > 0 && i%4==0)
        //         printf(" ");
        //     printf("%02x", ((uint8_t *) processed_message)[i] );
        // }
        // printf("\n");
    #endif

    #ifdef VERBOSE
        printf("Initialising digest...\n");
    #endif
    init_digest(digest_buffer);

    size_t num_blocks = buffer_length / WORDS_PER_BLOCK;
    for (size_t i = 0; i < num_blocks; i++)
    {
        #ifdef VERBOSE
            printf("Incorporating block %ld of %ld into digest\n", i, num_blocks);
        #endif
        process_block(processed_message + WORDS_PER_BLOCK*i, digest_buffer);
    }
}