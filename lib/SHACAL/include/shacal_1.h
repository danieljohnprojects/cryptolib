#pragma once

#include <stdint.h>

#define BYTES_PER_WORD 4
#define WORDS_PER_BLOCK 5
#define WORDS_PER_KEY 16
#define ROUNDS 80

typedef uint32_t block_t[WORDS_PER_BLOCK];
typedef uint32_t shacal_1_key_t[ROUNDS];

void
initialise_key(
    const uint32_t initial_key[WORDS_PER_KEY],
    shacal_1_key_t expanded_key
);

void encrypt(const shacal_1_key_t key, block_t block);
void decrypt(const shacal_1_key_t key, block_t block);