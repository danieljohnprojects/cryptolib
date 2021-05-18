/**
 * AES Encryption Round
 * 
 * Each round of encryption in AES consists of a substitution, a shift, a mix, and an addition of the round key.
 */

#include <AES.h>
#include <stdbool.h>
#include <stdint.h>

#include "AES_encr.h"
#include "AES_utils.h"

/**
 * Substitutes the bytes of a block according to the AES s-box.
 * 
 * @param in
 * 
 * @return A block with bytes substituted.
 */
static inline void subBlock(block_t *in, block_t *out)
{
    for (int i = 0; i < WORDS_PER_BLOCK; i++)
        out->words[i] = subword(in->words[i]);
    
    return;
}

/**
 * Rotate bytes in words depending on the position of the byte in the word.
 * 
 * This is done so that AES cannot be separated into four separate block 
 * ciphers.
 * 
 * @param in The block to be rotated.
 * 
 * @return The rotated block.
 */
static inline void shiftRows(block_t *in, block_t *out)
{
    for (int i = 0; i < BYTES_PER_BLOCK; i++)
        out->bytes[i] = in->bytes[ (i + (BYTES_PER_WORD * (i % BYTES_PER_WORD))) % BYTES_PER_BLOCK ];
    return;
}

/**
 * Performs a bytewise multiplication by two of a block where multiplication is 
 * performed in GF(2^8).
 * 
 * This is equivalent to a bitshift to the left by one unless the highest bit 
 * is set, then we also have to xor with 0x1b.
 * 
 * @param input A block of data to be doubled.
 * 
 * @return A block of data with each byte doubled.
 */
static inline void rijndaelDouble(block_t *in, block_t *twiceIn)
{
    for (int i = 0; i < WORDS_PER_BLOCK * BYTES_PER_WORD; i++)
        twiceIn->bytes[i] = ( in->bytes[i] << 1 ) ^ ( 0x1b & -(in->bytes[i] >> 7) );
}

/**
 * Performs the mixcolumns step of AES.
 * 
 * This is equivalent to treating the columns of a block of data as a cubic 
 * over GF(2^8) and multiplying by the fixed polynomial 3z^3 + z^2 + z + 2 
 * modulo z^4 + 1.
 * 
 * @param in The block that will have its columns mixed.
 * 
 * @return The result of the mixing.
 */
static inline void mixColumns(block_t *in, block_t *out)
{
    block_t twiceIn;
    rijndaelDouble(in, &twiceIn);
    
    for (int j = 0; j < 4; j++)
    {
        out->bytes[4*j] =                            /* b0 = sum of: */
            twiceIn.bytes[4*j] ^                             /* 2*a0 */
            twiceIn.bytes[4*j + 1] ^ in->bytes[4*j + 1] ^    /* 3*a1 */
            in->bytes[4*j + 2] ^                             /*   a2 */
            in->bytes[4*j + 3];                              /*   a3 */
        out->bytes[4*j + 1] =                        /* b1 = sum of: */
            in->bytes[4*j] ^                                 /*   a0 */
            twiceIn.bytes[4*j + 1] ^                         /* 2*a1 */
            twiceIn.bytes[4*j + 2] ^ in->bytes[4*j + 2] ^    /* 3*a2 */
            in->bytes[4*j + 3];                              /*   a3 */
        out->bytes[4*j + 2] =                        /* b2 = sum of: */
            in->bytes[4*j] ^                                 /*   a0 */
            in->bytes[4*j + 1] ^                             /*   a1 */
            twiceIn.bytes[4*j + 2] ^                         /* 2*a2 */
            twiceIn.bytes[4*j + 3] ^ in->bytes[4*j + 3];     /* 3*a3 */
        out->bytes[4*j + 3] =                        /* b2 = sum of: */
            twiceIn.bytes[4*j] ^ in->bytes[4*j] ^            /* 3*a0 */
            in->bytes[4*j + 1] ^                             /*   a1 */
            in->bytes[4*j + 2] ^                             /*   a2 */
            twiceIn.bytes[4*j + 3];                          /* 2*a3 */
    }
    return;
}

/**
 * Performs a encryption round on the given block.
 * 
 * Encryption round consists of the following steps:
 *  1. SBox byte substitution.
 *  2. Row shifting.
 *  3. Column mixing. (If not final round).
 */
void encryption_round(block_t *in, block_t *out, bool final)
{
    block_t subbed;
    subBlock(in, &subbed);
    if (final)
    {
        shiftRows(&subbed, out);
        return;
    }
    block_t shifted;
    shiftRows(&subbed, &shifted);    
    mixColumns(&shifted, out);
    return;
}