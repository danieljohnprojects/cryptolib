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
#include <MD4.h>

#include "constants.h"
#include "helper_functions.h"

void print_digest(const uint8_t digest[DIGEST_LENGTH])
{
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
    {
        if (i > 0 && i%4==0)
            printf(" ");
        printf("%02x", digest[i]);
    }
    printf("\n");
}

/**
 * @brief Computes the number of 32-bit words needed to store a message of the 
 * given length (in bytes), plus padding and the representation of the message 
 * length.
 * 
 * @param message_length The length of the unpadded message in butes.
 * @return The length of the corresponding buffer in words.
 */
size_t determine_padded_length(size_t message_length)
{
    size_t padding_length = ((PAD_REMAINDER - message_length - 1) % PAD_BLOCK) + 1;
    size_t length_length = PAD_BLOCK - PAD_REMAINDER;
    size_t byte_length = message_length + padding_length + length_length;

    return byte_length / 4;
}

/**
 * Fills a buffer with the given message and the appropriate padding.
 * 
 * @param message A pointer to an array of bytes constituting the message. Note 
 * that this is not necesarilly a string so does not need a null terminator.
 * @param message_length The length of the message in bytes.
 * @param buffer A pointer to an array that will store the processed 
 * message.
 * @param buffer_length The length of the buffer in 32-bit words.
 */
void preprocess(const uint8_t *message, 
                size_t message_length,
                uint32_t *buffer,
                size_t buffer_length) 
{
    for (size_t i = 0; i < buffer_length; i++)
        buffer[i] = 0UL;

    uint8_t *byte_buffer;
    byte_buffer = (uint8_t *) buffer;
    // Copy over the message
    size_t i = 0;
    for (; i < message_length; i++) {
        byte_buffer[i] = message[i];
    }
    byte_buffer[i] = 0x80;

    uint64_t *length_buffer = (uint64_t *) (&(buffer[buffer_length - 2]));
    *length_buffer = message_length * 8; // Length in *bits*
}

/**
 * @brief Initialises the digest to the starting values shown in Step 3.
 * 
 * @param digest A pointer to the digest to be initialised.
 */
void init_digest(uint8_t digest[DIGEST_LENGTH])
{
    digest[0] = 0x01;
    digest[1] = 0x23;
    digest[2] = 0x45;
    digest[3] = 0x67;
    digest[4] = 0x89;
    digest[5] = 0xab;
    digest[6] = 0xcd;
    digest[7] = 0xef;
    digest[8] = 0xfe;
    digest[9] = 0xdc;
    digest[10] = 0xba;
    digest[11] = 0x98;
    digest[12] = 0x76;
    digest[13] = 0x54;
    digest[14] = 0x32;
    digest[15] = 0x10;
}

/**
 * @brief Update the digest using the 16-word block from the message
 * 
 * @param message_block A block of 16 words from the message.
 * @param digest The digest of the hash
 */
void process_block(const uint32_t message_block[WORDS_PER_BLOCK], 
                   uint8_t digest[DIGEST_LENGTH])
{
    // printf("Contents of message block:\n");
    // for (size_t i = 0; i < 16*4; i++)
    // {
    //     if (i > 0 && i%4==0)
    //         printf(" ");
    //     printf("%02x", ((uint8_t *)message_block)[i] );
    // }
    // printf("\n");


    uint32_t *A = ((uint32_t *)digest) +  0;
    uint32_t *B = ((uint32_t *)digest) +  1;
    uint32_t *C = ((uint32_t *)digest) +  2;
    uint32_t *D = ((uint32_t *)digest) +  3;

    uint32_t a = *A;
    uint32_t b = *B;
    uint32_t c = *C;
    uint32_t d = *D;
    // printf("Initial digest state:\n");
    // print_digest(digest);

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
    // printf("Final digest state:\n");    
    // print_digest(digest);
}

/**
 * @brief Computes the MD4 digest of a message and stores it in the given 
 * buffer. 
 * 
 * @param message A string of bytes to digest.
 * @param message_length The length in bytes of the message.
 * @param digest A buffer that will store the resulting digest.
 */
void MD4digest(const uint8_t *message, 
               size_t message_length, 
               uint8_t digest[DIGEST_LENGTH])
{
    // printf("Recieved message of length %ld bytes.\n", message_length);
    size_t buffer_length = determine_padded_length(message_length);
    // printf("Creating buffer of length %ld bytes to hold processed message.\n", buffer_length*4);
    uint32_t processed_message[buffer_length];

    preprocess(message, message_length, processed_message, buffer_length);
    // printf("Original message:\n");
    // for (size_t i = 0; i < message_length; i++)
    //     printf("%02x", message[i]);
    // printf("\n");
    // printf("Processed message:\n");
    // for (size_t i = 0; i < buffer_length*4; i++)
    // {
    //     if (i > 0 && i%4==0)
    //         printf(" ");
    //     printf("%02x", ((uint8_t *) processed_message)[i] );
    // }
    // printf("\n");


    size_t num_blocks = buffer_length / WORDS_PER_BLOCK;

    init_digest(digest);

    for (size_t i = 0; i < num_blocks; i++)
    {
        // printf("Incorporating block %ld of %ld into digest\n", i, num_blocks);
        process_block(processed_message + WORDS_PER_BLOCK*i, digest);
    }
}