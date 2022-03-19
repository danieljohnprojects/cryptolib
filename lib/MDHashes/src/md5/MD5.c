/**
 * @file MD5.c
 * @brief An implementation of the MD5 hash function. 
 * 
 * The MD5 hash takes in an arbitrary length message and computes a 128-bit 
 * value. We follow the description given in RFC 1321:
 * http://www.faqs.org/rfcs/rfc1321.html
 * Except that we will always assume that messages are strings of bytes, rather
 * than of bits.
 * 
 * This code assumes little-endianness.
 */

#include <stdio.h>
#include <Hash.h>

#include "MD5.h"
#include "../setup.h"

/**
 * @brief Update the digest using the 16-word block from the message
 * 
 * @param message_block A block of 16 words from the message.
 * @param digest The digest of the hash
 */
void process_block(const uint32_t message_block[WORDS_PER_BLOCK], 
                   uint8_t digest[DIGEST_LENGTH])
{
    #ifdef VERBOSE
        printf("Contents of message block:\n");
        print_bytes((uint8_t *)message_block, WORDS_PER_BLOCK*4);
    #endif


    uint32_t *A = ((uint32_t *)digest) +  0;
    uint32_t *B = ((uint32_t *)digest) +  1;
    uint32_t *C = ((uint32_t *)digest) +  2;
    uint32_t *D = ((uint32_t *)digest) +  3;

    uint32_t a = *A;
    uint32_t b = *B;
    uint32_t c = *C;
    uint32_t d = *D;

    #ifdef VERBOSE
        printf("Initial digest state:\n");
        print_bytes(digest_buffer, DIGEST_LENGTH);
    #endif

    // Round 1
    FF(a, b, c, d, message_block[ 0], S11, 0xd76aa478);
    FF(d, a, b, c, message_block[ 1], S12, 0xe8c7b756);
    FF(c, d, a, b, message_block[ 2], S13, 0x242070db);
    FF(b, c, d, a, message_block[ 3], S14, 0xc1bdceee);
    FF(a, b, c, d, message_block[ 4], S11, 0xf57c0faf);
    FF(d, a, b, c, message_block[ 5], S12, 0x4787c62a);
    FF(c, d, a, b, message_block[ 6], S13, 0xa8304613);
    FF(b, c, d, a, message_block[ 7], S14, 0xfd469501);
    FF(a, b, c, d, message_block[ 8], S11, 0x698098d8);
    FF(d, a, b, c, message_block[ 9], S12, 0x8b44f7af);
    FF(c, d, a, b, message_block[10], S13, 0xffff5bb1);
    FF(b, c, d, a, message_block[11], S14, 0x895cd7be);
    FF(a, b, c, d, message_block[12], S11, 0x6b901122);
    FF(d, a, b, c, message_block[13], S12, 0xfd987193);
    FF(c, d, a, b, message_block[14], S13, 0xa679438e);
    FF(b, c, d, a, message_block[15], S14, 0x49b40821);
    // Round 2
    GG(a, b, c, d, message_block[ 1], S21, 0xf61e2562);
    GG(d, a, b, c, message_block[ 6], S22, 0xc040b340);
    GG(c, d, a, b, message_block[11], S23, 0x265e5a51);
    GG(b, c, d, a, message_block[ 0], S24, 0xe9b6c7aa);
    GG(a, b, c, d, message_block[ 5], S21, 0xd62f105d);
    GG(d, a, b, c, message_block[10], S22, 0x02441453);
    GG(c, d, a, b, message_block[15], S23, 0xd8a1e681);
    GG(b, c, d, a, message_block[ 4], S24, 0xe7d3fbc8);
    GG(a, b, c, d, message_block[ 9], S21, 0x21e1cde6);
    GG(d, a, b, c, message_block[14], S22, 0xc33707d6);
    GG(c, d, a, b, message_block[ 3], S23, 0xf4d50d87);
    GG(b, c, d, a, message_block[ 8], S24, 0x455a14ed);
    GG(a, b, c, d, message_block[13], S21, 0xa9e3e905);
    GG(d, a, b, c, message_block[ 2], S22, 0xfcefa3f8);
    GG(c, d, a, b, message_block[ 7], S23, 0x676f02d9);
    GG(b, c, d, a, message_block[12], S24, 0x8d2a4c8a);
    // Round 3
    HH(a, b, c, d, message_block[ 5], S31, 0xfffa3942);
    HH(d, a, b, c, message_block[ 8], S32, 0x8771f681);
    HH(c, d, a, b, message_block[11], S33, 0x6d9d6122);
    HH(b, c, d, a, message_block[14], S34, 0xfde5380c);
    HH(a, b, c, d, message_block[ 1], S31, 0xa4beea44);
    HH(d, a, b, c, message_block[ 4], S32, 0x4bdecfa9);
    HH(c, d, a, b, message_block[ 7], S33, 0xf6bb4b60);
    HH(b, c, d, a, message_block[10], S34, 0xbebfbc70);
    HH(a, b, c, d, message_block[13], S31, 0x289b7ec6);
    HH(d, a, b, c, message_block[ 0], S32, 0xeaa127fa);
    HH(c, d, a, b, message_block[ 3], S33, 0xd4ef3085);
    HH(b, c, d, a, message_block[ 6], S34, 0x04881d05);
    HH(a, b, c, d, message_block[ 9], S31, 0xd9d4d039);
    HH(d, a, b, c, message_block[12], S32, 0xe6db99e5);
    HH(c, d, a, b, message_block[15], S33, 0x1fa27cf8);
    HH(b, c, d, a, message_block[ 2], S34, 0xc4ac5665);
    // Round 4
    II(a, b, c, d, message_block[ 0], S41, 0xf4292244);
    II(d, a, b, c, message_block[ 7], S42, 0x432aff97);
    II(c, d, a, b, message_block[14], S43, 0xab9423a7);
    II(b, c, d, a, message_block[ 5], S44, 0xfc93a039);
    II(a, b, c, d, message_block[12], S41, 0x655b59c3);
    II(d, a, b, c, message_block[ 3], S42, 0x8f0ccc92);
    II(c, d, a, b, message_block[10], S43, 0xffeff47d);
    II(b, c, d, a, message_block[ 1], S44, 0x85845dd1);
    II(a, b, c, d, message_block[ 8], S41, 0x6fa87e4f);
    II(d, a, b, c, message_block[15], S42, 0xfe2ce6e0);
    II(c, d, a, b, message_block[ 6], S43, 0xa3014314);
    II(b, c, d, a, message_block[13], S44, 0x4e0811a1);
    II(a, b, c, d, message_block[ 4], S41, 0xf7537e82);
    II(d, a, b, c, message_block[11], S42, 0xbd3af235);
    II(c, d, a, b, message_block[ 2], S43, 0x2ad7d2bb);
    II(b, c, d, a, message_block[ 9], S44, 0xeb86d391);

    *A += a;
    *B += b;
    *C += c;
    *D += d;
    // printf("Final digest state:\n");    
    // print_digest(digest);
}


/**
 * @brief Computes the MD5 digest of a message and stores it in the given 
 * buffer. 
 * 
 * @param message A string of bytes to digest.
 * @param message_length The length in bytes of the message.
 * @param digest A buffer that will store the resulting digest.
 */
void digest(const uint8_t *message, 
            size_t message_length, 
            uint8_t digest[DIGEST_LENGTH])
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
        printf("Processed message:\n");
        print_bytes((uint8_t *) processed_message, buffer_length*4);
    #endif


    size_t num_blocks = buffer_length / WORDS_PER_BLOCK;

    init_digest(digest);

    for (size_t i = 0; i < num_blocks; i++)
    {
        #ifdef VERBOSE
            printf("Incorporating block %ld of %ld into digest\n", i, num_blocks);
        #endif
        process_block(processed_message + WORDS_PER_BLOCK*i, digest);
    }
}