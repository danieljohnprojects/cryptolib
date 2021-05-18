#include <AES.h>
#include <stdbool.h>

#include "AES_encr.h"
#include "AES_ks.h"
#include "AES_utils.h"

/**
 * Encrypt a block of data using AES.
 * 
 */
void encrypt(AES_key *key, block_t *in, block_t *out)
{
    block_t tmp;
    // Initial round key addition
    xor_blocks(&(key->schedule[0]), in, out);
    for (int round = 1; round < ROUND_KEYS; round++)
    {
        encryption_round(out, &tmp, false);
        xor_blocks(&tmp, &(key->schedule[round]), out);
    }
    encryption_round(out, &tmp, true);
    xor_blocks(&tmp, &(key->schedule[ROUND_KEYS]), out);
    return;
}