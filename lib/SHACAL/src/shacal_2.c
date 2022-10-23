/**
 * @file shacal_2.c
 * @author Daniel John (daniel.john.projects@gmail.com)
 * @brief An implementation of the SHACAL-2 block cipher.
 * @version 0.1
 * @date 2022-10-21
 * 
 * The SHACAL-2 block cipher is an ARX block cipher pulled 
 * from the SHA-2 hash function. I have not been able to 
 * track down any official documentation on the block cipher 
 * itself so I have used the FIPS documentation of SHA-2.
 */

#include <stdint.h>
#include <stdio.h>

#include <IO.h>
#include <shacal_2.h>

#define ROTATE_RIGHT(x, n) (((x) >> (n)) | ((x) << (32-(n))))

const uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline uint32_t
choice(uint32_t B, uint32_t C, uint32_t D) {
    return (B & C) | ((~B) & D);
}

static inline uint32_t
majority(uint32_t B, uint32_t C, uint32_t D) {
    return (B & C) ^ (B & D) ^ (C & D);
}

static inline uint32_t
S0(uint32_t x) {
    return ROTATE_RIGHT(x, 2) ^ ROTATE_RIGHT(x, 13) ^ ROTATE_RIGHT(x, 22);
}

static inline uint32_t
S1(uint32_t x) {
    return ROTATE_RIGHT(x, 6) ^ ROTATE_RIGHT(x, 11) ^ ROTATE_RIGHT(x, 25);
}

static inline uint32_t
s0(uint32_t x) {
    return ROTATE_RIGHT(x, 7) ^ ROTATE_RIGHT(x, 18) ^ (x >> 3);
}

static inline uint32_t
s1(uint32_t x) {
    return ROTATE_RIGHT(x, 17) ^ ROTATE_RIGHT(x, 19) ^ (x >> 10);
}

void
initialise_key(
    const uint32_t initial_key[WORDS_PER_KEY],
    shacal_2_key_t expanded_key
) {
    size_t t = 0;
    for (; t < WORDS_PER_KEY; t++) {
        expanded_key[t] = initial_key[t];
    }
    for (; t < ROUNDS; t++) {
        expanded_key[t] = s1(expanded_key[t-2]) + 
            expanded_key[t-7] +
            s0(expanded_key[t-15]) +
            expanded_key[t-16];
    }
    #ifdef VERBOSE
    printf("Expanded key before adding round constants:\n");
    print_words32(expanded_key, ROUNDS);
    #endif

    for (t = 0; t < ROUNDS; t++) {
        expanded_key[t] += K[t];
    }

    #ifdef VERBOSE
    printf("\nExpanded key after adding round constants:\n");
    print_words32(expanded_key, ROUNDS);
    #endif
}

static void
encryption_round(
    block_t block
) {
    uint32_t *A = &block[0];
    uint32_t *B = &block[1];
    uint32_t *C = &block[2];
    uint32_t *D = &block[3];
    uint32_t *E = &block[4];
    uint32_t *F = &block[5];
    uint32_t *G = &block[6];
    uint32_t *H = &block[7];
    uint32_t T1 = *H + S1(*E) + choice(*E, *F, *G);
    uint32_t T2 = S0(*A) + majority(*A, *B, *C);
    *H = *G;
    *G = *F;
    *F = *E;
    *E = *D + T1;
    *D = *C;
    *C = *B;
    *B = *A;
    *A = T1 + T2;
}

static void
decryption_round(
    block_t block
) {
    uint32_t *A = &block[0];
    uint32_t *B = &block[1];
    uint32_t *C = &block[2];
    uint32_t *D = &block[3];
    uint32_t *E = &block[4];
    uint32_t *F = &block[5];
    uint32_t *G = &block[6];
    uint32_t *H = &block[7];
    uint32_t T2 = S0(*B) + majority(*B, *C, *D);
    uint32_t T1 = *A - T2;
    *A = *B;
    *B = *C;
    *C = *D;
    *D = *E - T1;
    *E = *F;
    *F = *G;
    *G = *H;
    *H = T1 - (S1(*E) + choice(*E, *F, *G));
}

static inline void
key_add(block_t block, uint32_t round_key) {
    block[0] += round_key;
    block[4] += round_key;
}

void
encrypt(const shacal_2_key_t key, block_t block) {
    int t = 0;
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
    for (; t < 1; t++) {
        encryption_round(block);
        key_add(block, key[t]);
    }
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
    for (; t < 2; t++) {
        encryption_round(block);
        key_add(block, key[t]);
    }
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
    for (; t < 48; t++) {
        encryption_round(block);
        key_add(block, key[t]);
    }
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
    for (; t < 64; t++) {
        encryption_round(block);
        key_add(block, key[t]);
    }
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
}

void
decrypt(const shacal_2_key_t key, block_t block) {
    int t = 0;
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
    for (; t < 16; t++) {
        key_add(block, -key[64 - t - 1]);
        decryption_round(block);
    }
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
    for (; t < 32; t++) {
        key_add(block, -key[64 - t - 1]);
        decryption_round(block);
    }
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
    for (; t < 48; t++) {
        key_add(block, -key[64 - t - 1]);
        decryption_round(block);
    }
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
    for (; t < 64; t++) {
        key_add(block, -key[64 - t - 1]);
        decryption_round(block);
    }
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
}
