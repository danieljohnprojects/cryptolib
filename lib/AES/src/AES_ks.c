/**
 * AES Key Schedule 
 * 
 * AES derives a sequence of keys from the initial key using rotation and 
 * substitution operations on the individual words of the key. Each of the keys 
 * derived in this way are applied at the beginning of an encryption round. The 
 * key derivation function is slightly different depending on the key length. 
 * 
 * The key bit length is determined by a #define of AES128, AES192, or AES256.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include <AES.h>
#include "AES_ks.h"

/////////////////// KEY SCHEDULING //

const uint8_t sbox[] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
static uint32_t rcon[] = {
    0x00000000,
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 
    0x1b000000, 0x36000000};

/**
 * Rotates a word one byte to the left.
 * 
 * That is:
 * [b0,b1,b2,b3] -> [b1,b2,b3,b0]
 * 
 * @param word  A word (32 bits long) to be rotated.
 * 
 * @return The rotated word.
 */
uint32_t rotword(uint32_t word)
{
    return (word << BITS_PER_BYTE) ^ (word >> ((BYTES_PER_WORD - 1) * (BITS_PER_BYTE)));
}

/**
 * Substitutes the bytes of a word according to the AES sbox.
 * 
 * That is:
 * [b0,b1,b2,b3] -> [S(b0), S(b1), S(b2), S(b3)]
 * 
 * @param word A word (32 bits long) to be substituted.
 * 
 * @return The substituted word.
 */
uint32_t subword(uint32_t word)
{
    uint32_t b3 = sbox[(word&0xff)];
    uint32_t b2 = sbox[(word&0xff00) >> BITS_PER_BYTE];
    uint32_t b1 = sbox[(word&0xff0000) >> 2*BITS_PER_BYTE];
    uint32_t b0 = sbox[(word&0xff000000) >> 3*BITS_PER_BYTE];

    return (b0 << 3*BITS_PER_BYTE) ^ (b1 << 2*BITS_PER_BYTE) ^ (b2 << BITS_PER_BYTE) ^ b3;
}

/**
 * Initialise a key data structure with the given key as the initial key.
 * 
 * @param initial_key   A pointer to a buffer of uint32_t's of length WORDS_PER_KEY
 * @param expanded_key  A pointer to an AES_key data structure that will hold the expanded key schedule. 
 */
void initialise_key(const uint32_t initial_key[WORDS_PER_KEY], AES_key *expanded_key)
{
    // First copy the initial key across
    for (int i = 0; i < WORDS_PER_KEY; i++)
        expanded_key->word_list[i] = initial_key[i];
    
    // Then compute the resulting keyschedule
    #ifndef AES256
    for (int i = WORDS_PER_KEY; i < WORDS_PER_ROUND_KEY*(ROUND_KEYS + 1); i++)
    {
        if (i%WORDS_PER_KEY == 0)
            expanded_key->word_list[i] = 
                expanded_key->word_list[i-WORDS_PER_KEY] ^ 
                subword(rotword(expanded_key->word_list[i-1])) ^
                rcon[i / WORDS_PER_KEY];
        else
            expanded_key->word_list[i] = 
                expanded_key->word_list[i-WORDS_PER_KEY] ^ 
                expanded_key->word_list[i-1];
    }
    #endif
    #ifdef AES256
    // In 256 bit case we need to do some extra substitution.
    for (int i = WORDS_PER_KEY; i < WORDS_PER_ROUND_KEY*(ROUND_KEYS + 1); i++)
    {
        if (i % WORDS_PER_KEY == 0)
            expanded_key->word_list[i] = 
                expanded_key->word_list[i-WORDS_PER_KEY] ^ 
                subword(rotword(expanded_key->word_list[i-1])) ^
                rcon[i / WORDS_PER_KEY];
        else if (i % WORDS_PER_KEY == 4) // Special extra stuff for 256 bit
            expanded_key->word_list[i] = 
                expanded_key->word_list[i-WORDS_PER_KEY] ^ 
                subword(expanded_key->word_list[i-1]);
        else
            expanded_key->word_list[i] = 
                expanded_key->word_list[i-WORDS_PER_KEY] ^ 
                expanded_key->word_list[i-1];
    }
    #endif
    /*
    expanded_key->key_schedule[0][0] = 
        subword(rotword(expanded_key->initial_key[WORDS_PER_KEY - 1])) ^ 
        expanded_key->initial_key[0] ^
        rcon[0];

    #ifndef AES256
    for (int i = 1; i < WORDS_PER_KEY; i++)
        expanded_key->key_schedule[0][i] = 
            expanded_key->key_schedule[0][i-1] ^
            expanded_key->initial_key[i];

    for (int round = 1; round < ROUND_KEYS; round++)
    {
        expanded_key -> key_schedule[round][0] = 
            subword(rotword(expanded_key->key_schedule[round - 1][WORDS_PER_KEY - 1])) ^
            expanded_key->key_schedule[round-1][0] ^ 
            rcon[round];

        for (int i = 1; i < WORDS_PER_KEY; i++)
            expanded_key->key_schedule[round][i] = 
                expanded_key->key_schedule[round][i-1] ^ expanded_key->key_schedule[round-1][i];
    }
    #endif
    #ifdef AES256
    for (int i = 1; i < WORDS_PER_KEY; i++)
        expanded_key->key_schedule[0][i] = 
            subword(expanded_key->key_schedule[0][i-1]) ^
            expanded_key->initial_key[i];
    for (int round = 1; round < ROUND_KEYS; round++)
    {
        expanded_key -> key_schedule[round][0] = 
            subword(rotword(expanded_key->key_schedule[round - 1][WORDS_PER_KEY - 1])) ^
            expanded_key->key_schedule[round-1][0] ^
            rcon[round];
        for (int i = 1; i < WORDS_PER_KEY; i++)
            expanded_key->key_schedule[round][i] = 
                subword(expanded_key->key_schedule[round][i-1]) ^ expanded_key->key_schedule[round-1][i];
    }
    #endif */
}