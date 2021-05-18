/**
 * AES Encryption Round
 * 
 * Each round of encryption in AES consists of a substitution, a shift, a mix, and an addition of the round key.
 */

#include <AES.h>
#include <stdbool.h>
#include <stdint.h>

#include "AES_encr.h"
#include "AES_sbox.h"

/**
 * Performs a encrytption round on the given block.
 * 
 * Changes are made in place.
 * Encryption round consists of the following steps:
 *  1. SBox byte substitution.
 *  2. Row shifting.
 *  3. Column mixing. (If not final round).
 */
block_t encryption_round(block_t *input, bool final)
{
    block_t output = {.words = {0x00000000, 0x00000000, 0x00000000, 0x00000000}};
    return output;
}