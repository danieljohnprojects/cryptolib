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

/**
 * Data block struct.
 */
typedef union block_t 
{
    uint32_t words[WORDS_PER_BLOCK];
    uint8_t bytes[WORDS_PER_BLOCK * BYTES_PER_WORD];
} block_t;

/**
 * Data structure for storing key schedule for AES.
 */
typedef union AES_key
{
    // C is row major ordered so second index varies the fastest.
    block_t schedule[ROUND_KEYS + 1];
    uint32_t word_list[(ROUND_KEYS + 1) * WORDS_PER_BLOCK];
} AES_key;
