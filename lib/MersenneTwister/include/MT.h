#pragma once

#include <stdint.h>

#define W 32
#define N 624
#define M 397
#define UMASK 0x80000000
#define LMASK 0x7FFFFFFF
#define A 0x9908B0DF
#define U 11
#define D 0xFFFFFFFF
#define S 7
#define B 0x9D2C5680
#define T 15
#define C 0xEFC60000
#define L 18
#define F 1812433253

/**
 * Initialises the RNG state with the given seed.
 * 
 * @param seed The 32 bit seed value.
 * @param state An array to hold the state.
 */
void set_seed(uint32_t seed, uint32_t state[N]);

/**
 * Refreshes the state array.
 * 
 * @param state The array holding the initialised state.
 */
void twist(uint32_t state[N]);

/**
 * Extract the 32-bit value held in the state array at a particular index.
 * 
 * @param state The array holding the initialised state.
 * @param index The index of the array to extract from.
 */
uint32_t extract32(uint32_t state[N], int index);