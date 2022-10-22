/**
 * @file SHACAL_1_encr.c
 * @author Daniel John (daniel.john.projects@gmail.com)
 * @brief An implementation of the SHACAL-1 block cipher.
 * @version 0.1
 * @date 2022-10-21
 * 
 * The SHACAL-1 block cipher is an ARX block cipher pulled 
 * from the SHA-1 hash function. I have not been able to 
 * track down any official documentation on the block cipher 
 * itself so I have used the FIPS documentation of SHA-1.
 */

#include <IO.h>
#include <shacal_1.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define K0 0x5A827999
#define K1 0x6ED9EBA1
#define K2 0x8F1BBCDC
#define K3 0xCA62C1D6

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

static inline uint32_t
f0(uint32_t B, uint32_t C, uint32_t D) {
    return (B & C) | ((~B) & D);
}

static inline uint32_t
f1(uint32_t B, uint32_t C, uint32_t D) {
    return B^C^D;
}

static inline uint32_t
f2(uint32_t B, uint32_t C, uint32_t D) {
    return (B & C) | (B & D) | (C & D);
}

static inline uint32_t
f3(uint32_t B, uint32_t C, uint32_t D) {
    return B^C^D;
}

void
initialise_key(
    const uint8_t initial_key[BYTES_PER_KEY],
    shacal_1_key_t expanded_key
) {
    uint64_t t = 0;
    for (; t < BYTES_PER_KEY/BYTES_PER_WORD; t++) {
        expanded_key[t] = ((uint32_t *) initial_key)[t];
    }

    for (; t < ROUNDS; t++) {
        expanded_key[t] = ROTATE_LEFT(expanded_key[t-3] ^ expanded_key[t-8] ^ expanded_key[t-14] ^ expanded_key[t-16], 1);
    }

    #ifdef VERBOSE
    printf("Expanded key before adding round constants:\n");
    print_words32(expanded_key, 80);
    #endif

    for (t = 0; t < 20; t++) {
        expanded_key[t] += K0;
    }
    for (; t < 40; t++) {
        expanded_key[t] += K1;
    }
    for (; t < 60; t++) {
        expanded_key[t] += K2;
    }
    for (; t < 80; t++) {
        expanded_key[t] += K3;
    }
    
    #ifdef VERBOSE
    printf("\nExpanded key after adding round constants:\n");
    print_words32(expanded_key, 80);
    printf("\n");
    #endif
}

/**
 * @brief Performs one round of SHACAL-1 encryption in place.
 * 
 * @param block A buffer containing the data to be encrypted.
 * @param round_function A function that is applied to three words on the input block.
 */
static void
encryption_round(
    block_t block, 
    uint32_t (*round_function)(uint32_t, uint32_t, uint32_t)
) {
    uint32_t *A = &block[0];
    uint32_t *B = &block[1];
    uint32_t *C = &block[2];
    uint32_t *D = &block[3];
    uint32_t *E = &block[4];
    uint32_t tmp = round_function(*B, *C, *D);
    tmp += *E + ROTATE_LEFT(*A, 5);
    *E = *D;
    *D = *C;
    *C = ROTATE_LEFT(*B, 30);
    *B = *A;
    *A = tmp;
}

static void 
decryption_round(
    block_t block,
    uint32_t (*round_function)(uint32_t, uint32_t, uint32_t)
) {
    uint32_t *A = &block[0];
    uint32_t *B = &block[1];
    uint32_t *C = &block[2];
    uint32_t *D = &block[3];
    uint32_t *E = &block[4];
    uint32_t tmp = round_function(ROTATE_LEFT(*C, 2), *D, *E);
    tmp = *A - tmp - ROTATE_LEFT(*B, 5);
    *A = *B;
    *B = ROTATE_LEFT(*C, 2);
    *C = *D;
    *D = *E;
    *E = tmp;
}

static inline void
key_add(block_t block, uint32_t round_key) {
    block[0] += round_key;
}

void
encrypt(const shacal_1_key_t key, block_t block) {
    int t = 0;
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
    for (; t < 20; t++) {
        encryption_round(block, f0);
        key_add(block, key[t]);
    } 
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
    for (; t < 40; t++) {
        encryption_round(block, f1);
        key_add(block, key[t]);
    } 
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
    for (; t < 60; t++) {
        encryption_round(block, f2);
        key_add(block, key[t]);
    } 
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
    for (; t < 80; t++) {
        encryption_round(block, f3);
        key_add(block, key[t]);
    } 
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
}

void
decrypt(const shacal_1_key_t key, block_t block) {
    int t = 0;
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
    for (; t < 20; t++) {
        key_add(block, -key[80 - t - 1]);
        decryption_round(block, f3);
    } 
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
    for (; t < 40; t++) {
        key_add(block, -key[80 - t - 1]);
        decryption_round(block, f2);
    } 
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
    for (; t < 60; t++) {
        key_add(block, -key[80 - t - 1]);
        decryption_round(block, f1);
    }
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
    for (; t < 80; t++) {
        key_add(block, -key[80 - t - 1]);
        decryption_round(block, f0);
    } 
    #ifdef VERBOSE
    printf("State after %i rounds:\n", t);
    print_words32(block, WORDS_PER_BLOCK);
    #endif
}