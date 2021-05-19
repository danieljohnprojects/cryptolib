#pragma once

#include <stdint.h>

#ifdef AES128
    #define WORDS_PER_KEY   4
    #define ROUND_KEYS      10
#endif
#ifdef AES192
    #define WORDS_PER_KEY   6
    #define ROUND_KEYS      12
#endif
#ifdef AES256
    #define WORDS_PER_KEY   8
    #define ROUND_KEYS      14
#endif

#define BITS_PER_BYTE   8
#define BYTES_PER_WORD  4
#define WORDS_PER_BLOCK 4
#define BYTES_PER_BLOCK 16

/**
 * Data block struct.
 * 
 * Data should always be entered as a list of bytes, rather than words to 
 * prevent confusion due to endian-ness of the machine. Most operations should 
 * make use of the .bytes interface. 
 * The .words interface can be used to perform multiple byte operations in 
 * parallel. For example testing equality or xoring.
 */
typedef union block_t 
{
    uint8_t bytes[WORDS_PER_BLOCK * BYTES_PER_WORD];
    uint32_t words[WORDS_PER_BLOCK];
} block_t;

/**
 * Data structure for storing key schedule for AES.
 */
typedef union AES_key
{
    block_t schedule[ROUND_KEYS + 1];
    uint32_t word_list[(ROUND_KEYS + 1) * WORDS_PER_BLOCK];
} AES_key;

void initialise_key(
    const uint8_t initial_key[WORDS_PER_KEY * BYTES_PER_WORD], 
    AES_key *expanded_key
    );

void encrypt(AES_key *key, block_t *in, block_t *out);
void decrypt(AES_key *key, block_t *in, block_t *out);