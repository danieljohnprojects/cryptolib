/**
 * AES Encryption Round
 * 
 * Each round of encryption in AES consists of a substitution, a shift, a mix, 
 * and an addition of the round key.
 */

#include <AES.h>
#include <stdbool.h>
#include <stdint.h>

#include "AES_encr.h"

static const uint8_t sbox[] = {
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
static inline uint32_t subword(uint32_t word)
{
    uint32_t b3 = sbox[(word & 0xff)];
    uint32_t b2 = sbox[(word & 0xff00) >> BITS_PER_BYTE];
    uint32_t b1 = sbox[(word & 0xff0000) >> 2 * BITS_PER_BYTE];
    uint32_t b0 = sbox[(word & 0xff000000) >> 3 * BITS_PER_BYTE];

    return (b0 << 3 * BITS_PER_BYTE) ^ (b1 << 2 * BITS_PER_BYTE) ^ (b2 << BITS_PER_BYTE) ^ b3;
}

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
        out->bytes[i] = in->bytes[(i + (BYTES_PER_WORD * (i % BYTES_PER_WORD))) % BYTES_PER_BLOCK];
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
        twiceIn->bytes[i] = (in->bytes[i] << 1) ^ (0x1b & -(in->bytes[i] >> 7));
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
        out->bytes[4 * j] =                                   /* b0 = sum of: */
            twiceIn.bytes[4 * j] ^                            /* 2*a0 */
            twiceIn.bytes[4 * j + 1] ^ in->bytes[4 * j + 1] ^ /* 3*a1 */
            in->bytes[4 * j + 2] ^                            /*   a2 */
            in->bytes[4 * j + 3];                             /*   a3 */
        out->bytes[4 * j + 1] =                               /* b1 = sum of: */
            in->bytes[4 * j] ^                                /*   a0 */
            twiceIn.bytes[4 * j + 1] ^                        /* 2*a1 */
            twiceIn.bytes[4 * j + 2] ^ in->bytes[4 * j + 2] ^ /* 3*a2 */
            in->bytes[4 * j + 3];                             /*   a3 */
        out->bytes[4 * j + 2] =                               /* b2 = sum of: */
            in->bytes[4 * j] ^                                /*   a0 */
            in->bytes[4 * j + 1] ^                            /*   a1 */
            twiceIn.bytes[4 * j + 2] ^                        /* 2*a2 */
            twiceIn.bytes[4 * j + 3] ^ in->bytes[4 * j + 3];  /* 3*a3 */
        out->bytes[4 * j + 3] =                               /* b2 = sum of: */
            twiceIn.bytes[4 * j] ^ in->bytes[4 * j] ^         /* 3*a0 */
            in->bytes[4 * j + 1] ^                            /*   a1 */
            in->bytes[4 * j + 2] ^                            /*   a2 */
            twiceIn.bytes[4 * j + 3];                         /* 2*a3 */
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

/**
 * Compute bytewise xor of two blocks.
 * 
 * @param b1
 * @param b2
 * @param result a buffer to hold the result.
 */
static void xor_blocks(block_t *b1, block_t *b2, block_t *result)
{
    for (int i = 0; i < WORDS_PER_BLOCK; i++)
        result->words[i] = b1->words[i] ^ b2->words[i];
    return;
}

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