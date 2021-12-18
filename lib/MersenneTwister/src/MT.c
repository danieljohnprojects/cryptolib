/**
 * An implementation of the Mersenne Twister RNG, following the pseudocode 
 * given on wikipedia with the following constants:
 *  w = 32 bits (word size)
 *  n = 624 (degree of recurrence)
 *  m = 397 (middle word, an offset used in the recurrence relation)
 *  r = 31 (the number of bits of the lower bitmask)
 *  a = 0x9908B0DF(coefficients of the rational normal form twist matrix)
 *  u = 11
 *  d = 0xFFFFFFFF
 *  s = 7
 *  b = 0x9D2C5680
 *  t = 15
 *  c = 0xEFC60000
 *  l = 18
 * 
 * First we define a sequence x_k of w-bit vectors with the following 
 * recurrence relation:
 * x_{k+n} = x_{k+m} + ((x_k^u| x_{k+1}^l)A)
 * Were addition is over the  w-dimensional vector space over GF(2), and x_k^u 
 * and x_{k+1}^l mean the upper w-r bits of x_k and lower r bits of x_{k+1} 
 * respectively. A is a matrix (twist transformation) that ends up doing:
 * xA = x >> 1          if the lowest bit is zero
 *    = (x >> 1) + a    otherwise
 * 
 * From this sequence we generate the output sequence z_k as follows:
 * y1_k = x_k + ((x_k >> u) & d)
 * y2_k = y1_k + ((y1_k << s) & b)
 * y3_k = y2_k + ((y2_k << t) & t)
 * z_k = y3_k + (y3_k >> l)
 * 
 * In order to initialise the sequence x_k we need n (624) starting values. To 
 * do this we need one more constant:
 * f = 1812433253
 * then start with a seed value x_0 and generate x_1,...,x_{n-1} according to 
 * the following recurrence:
 * x_i = f * (x_{i-1} + (x_{i-1} >> (w-2))) + i
 * Where the first addition is done over the GF(2) vector space and the 
 * multiplication and second addition are done as w-bit integers.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include <MT.h>


/**
 * Initialises the RNG state with the given seed.
 * 
 * @param seed The 32 bit seed value.
 * @param state An array to hold the state.
 */
void set_seed(uint32_t seed, uint32_t state[N])
{
    // printf("Received seed %d\n", seed);
    state[0] = seed;
    for (int i = 1; i < N; i++)
        state[i] = F * (state[i-1] ^ (state[i-1] >> (W-2))) + i;
    // printf("First four numbers in state:\n");
    // printf("%u\n", state[0]);
    // printf("%u\n", state[1]);
    // printf("%u\n", state[2]);
    // printf("%u\n", state[3]);
}

/**
 * Refreshes the state array.
 * 
 * @param state The array holding the initialised state.
 */
void twist(uint32_t state[N])
{
    for (int i = 0; i < N; i++)
    {
        uint32_t x = (state[i]&UMASK) | (state[(i+1)%N]&LMASK);
        uint32_t x1 = x >> 1;
        if (x % 2)
            x1 ^= A;
        state[i] = x1 ^ state[(i+M) % N];
    }
}

/**
 * Extract the 32-bit value held in the state array at a particular index.
 * 
 * @param state The array holding the initialised state.
 * @param index The index of the array to extract from.
 */
uint32_t extract32(uint32_t state[N], int index)
{
    assert(index < N);
    assert(index > -1);

    uint32_t y = state[index];
    y ^= (y >> U) & D; // No effect for 32 bit version
    y ^= (y << S) & B;
    y ^= (y << T) & C;

    return y ^ (y>>L);
}