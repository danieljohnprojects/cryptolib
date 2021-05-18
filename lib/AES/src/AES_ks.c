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
#include "AES_utils.h"

/////////////////// KEY SCHEDULING //

// Round constants
static const uint32_t rcon[] = {
    0x00000000,
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 
    0x1b000000, 0x36000000};


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
    for (int i = WORDS_PER_KEY; i < WORDS_PER_BLOCK*(ROUND_KEYS + 1); i++)
    {
        if (i%WORDS_PER_KEY == 0)
            expanded_key->word_list[i] = 
                expanded_key->word_list[i-WORDS_PER_KEY] ^ 
                subword(rotword(expanded_key->word_list[i-1], 1)) ^
                rcon[i / WORDS_PER_KEY];
        else
            expanded_key->word_list[i] = 
                expanded_key->word_list[i-WORDS_PER_KEY] ^ 
                expanded_key->word_list[i-1];
    }
    #endif
    #ifdef AES256
    // In 256 bit case we need to do some extra substitution.
    for (int i = WORDS_PER_KEY; i < WORDS_PER_BLOCK*(ROUND_KEYS + 1); i++)
    {
        if (i % WORDS_PER_KEY == 0)
            expanded_key->word_list[i] = 
                expanded_key->word_list[i-WORDS_PER_KEY] ^ 
                subword(rotword(expanded_key->word_list[i-1], 1)) ^
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
}