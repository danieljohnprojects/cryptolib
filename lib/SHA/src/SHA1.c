/**
 * @file SHA1.c
 * @brief An implementation of the SHA1 hash function. 
 * 
 * The SHA1 hash takes in an arbitrary length message and computes a 160-bit 
 * value. We approximately follow the description given in RFC 3174:
 * http://www.faqs.org/rfcs/rfc3174.html
 * 
 * The key difference is that we do not initialise the digest buffer to the 
 * correct values. This makes it more convenient to perform length extension 
 * attacks but passes the burden of initialisation to the user when computing a 
 * regular hash.
 * 
 * We will always assume that messages are strings of bytes, rather than of 
 * bits.
 * 
 * This code assumes little-endianness, there are two loops that you should 
 * remove to make it work on a big endian machine, this hasn't been tested 
 * though.
 */

#include <stdio.h>
#include <Hash.h>
#include <IO.h>

#include "constants.h"


/**
 * @brief Computes the number of 32-bit words needed to store a message of the 
 * given length (in bytes), plus padding and the representation of the message 
 * length.
 * 
 * @param message_length The length of the unpadded message in bytes.
 * @return The length of the corresponding buffer in words.
 */
static size_t determine_padded_length(size_t message_length)
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
 * that this is not necessarily a string so does not need a null terminator.
 * @param message_length The length of the message in bytes.
 * @param prefix_length The length of the original message  not including any 
 * padding (0 unless performing a length extension attack).
 * @param buffer A pointer to an array that will store the processed message.
 * @param buffer_length The length of the buffer in 32-bit words.
 */
static void preprocess(const uint8_t *message, 
                       size_t message_length,
                       size_t prefix_length,
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

    // Store the bit-length of the message as a bigendian number at the end of the buffer.
    if (prefix_length)
        prefix_length = 4*determine_padded_length(prefix_length);
    message_length = (message_length + prefix_length) * 8;
    uint8_t *length_ptr = ((uint8_t *) (buffer + buffer_length)) - 1;
    for (i = 0; i < PAD_BLOCK - PAD_REMAINDER; i++)
    {
        *(length_ptr - i) = message_length & 0xff;
        message_length >>= 8;
    }

}


// /**
//  * @brief Initialises the digest to the starting values H0, H1, H2, H3, 
//  * H4 in step 6.
//  * 
//  * @param digest A pointer to the digest to be initialised.
//  */
// static void init_digest(uint32_t digest[DIGEST_WORD_LENGTH])
// {
//     digest[0] = 0x01234567;
//     digest[1] = 0x89abcdef;
//     digest[2] = 0xfedcba98;
//     digest[3] = 0x76543210;
//     digest[4] = 0xf0e1d2c3;
// }


/**
 * @brief Update the digest using the 16-word block from the message
 * 
 * @param message_block A block of 16 words from the message.
 * @param digest The digest of the hash
 */
static void process_block(const uint32_t message_block[WORDS_PER_BLOCK], 
                          uint32_t digest[DIGEST_WORD_LENGTH])
{
    #ifdef VERBOSE
        printf("Contents of message block:\n");
        print_bytes((uint8_t *)message_block, WORDS_PER_BLOCK*4);
    #endif

    #ifdef VERBOSE
        printf("Initial digest state:\n");
        print_bytes((uint8_t *) digest, DIGEST_LENGTH);
    #endif

    uint32_t W[80];

    size_t t = 0;
    for (; t < WORDS_PER_BLOCK; t++)
    {
        // Need to account for annoying endianness
        W[t] = (message_block[t] & 0xff000000) >> 24;
        W[t] |= (message_block[t] & 0xff0000) >> 8;
        W[t] |= (message_block[t] & 0xff00) << 8;
        W[t] |= (message_block[t] & 0xff) << 24;

    }
    for (; t < 80; t++)
        W[t] = ROTATE_LEFT(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);

    #ifdef VERBOSE
        printf("Internal state:\n");
        print_bytes((uint8_t *) W, 80*4);
    #endif

    uint32_t A = digest[0];
    uint32_t B = digest[1];
    uint32_t C = digest[2];
    uint32_t D = digest[3];
    uint32_t E = digest[4];

    uint32_t temp;

    for (t = 0; t < 20; t++)
    {
        temp = ROTATE_LEFT(A, 5) + F0(B,C,D) + E + W[t] + K0;
        E = D;
        D = C;
        C = ROTATE_LEFT(B, 30);
        B = A;
        A = temp;
    }
    #ifdef VERBOSE
        printf("Internal state after 20 rounds:\n");
        printf("A: %08x \nB: %08x \nC: %08x \nD: %08x \nE: %08x \n", A, B, C, D, E);
    #endif

    for (; t < 40; t++)
    {
        temp = ROTATE_LEFT(A, 5) + F1(B,C,D) + E + W[t] + K1;
        E = D;
        D = C;
        C = ROTATE_LEFT(B, 30);
        B = A;
        A = temp;
    }
    #ifdef VERBOSE
        printf("Internal state after 40 rounds:\n");
        printf("A: %08x \nB: %08x \nC: %08x \nD: %08x \nE: %08x \n", A, B, C, D, E);
    #endif

    for (; t < 60; t++)
    {
        temp = ROTATE_LEFT(A, 5) + F2(B,C,D) + E + W[t] + K2;
        E = D;
        D = C;
        C = ROTATE_LEFT(B, 30);
        B = A;
        A = temp;
    }
    #ifdef VERBOSE
        printf("Internal state after 60 rounds:\n");
        printf("A: %08x \nB: %08x \nC: %08x \nD: %08x \nE: %08x \n", A, B, C, D, E);
    #endif

    for (; t < 80; t++)
    {
        temp = ROTATE_LEFT(A, 5) + F3(B,C,D) + E + W[t] + K3;
        E = D;
        D = C;
        C = ROTATE_LEFT(B, 30);
        B = A;
        A = temp;
    }
    #ifdef VERBOSE
        printf("Internal state after 80 rounds:\n");
        printf("A: %08x \nB: %08x \nC: %08x \nD: %08x \nE: %08x \n", A, B, C, D, E);
    #endif

    digest[0] += A;
    digest[1] += B;
    digest[2] += C;
    digest[3] += D;
    digest[4] += E;
}


/**
 * @brief Computes the SHA1 digest of a message and stores it in the given 
 * buffer. 
 * 
 * @param message A string of bytes to digest.
 * @param message_length The length of the message measured in bytes.
 * @param prefix_length The length of the original message not including any 
 * padding (0 unless performing a length extension attack).
 * @param digest_buffer A buffer that will store the resulting digest.
 */
void sha1digest(const uint8_t *message, 
               size_t message_length,
               size_t prefix_length,
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

    preprocess(message, message_length, prefix_length, processed_message, buffer_length);
    #ifdef VERBOSE
        printf("Original message:\n");
        print_bytes(message, message_length);
        printf("Processed message:\n");
        print_bytes((uint8_t *) processed_message, buffer_length*4);
    #endif


    size_t num_blocks = buffer_length / WORDS_PER_BLOCK;

    uint32_t *digest_words = (uint32_t *) digest_buffer;
    
    // init_digest(digest_words);

    size_t i;

    // If you are working on a big-endian machine you should remove this loop.
    for (i = 0; i < DIGEST_WORD_LENGTH; i++)
        digest_words[i] = MIRROR_32(digest_words[i]);

    for (i = 0; i < num_blocks; i++)
    {
        #ifdef VERBOSE
            printf("Incorporating block %ld of %ld into digest\n", i, num_blocks);
        #endif
        process_block(processed_message + WORDS_PER_BLOCK*i, digest_words);
    }

    // If you are working on a big-endian machine you should remove this loop.
    for (i = 0; i < DIGEST_WORD_LENGTH; i++)
        digest_words[i] = MIRROR_32(digest_words[i]);
}