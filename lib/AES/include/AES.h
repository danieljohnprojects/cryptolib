#include <stdint.h>

// #define AES128

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
#define WORDS_PER_ROUND_KEY 4

/**
 * Data structure for storing key schedule for AES.
 */
typedef union AES_key
{
    // C is row major ordered so second index varies the fastest.
    uint32_t schedule[ROUND_KEYS + 1][WORDS_PER_ROUND_KEY];
    uint32_t word_list[(ROUND_KEYS + 1) * WORDS_PER_ROUND_KEY];
} AES_key;


void initialise_key(uint32_t *initial_key, AES_key *expanded_key);