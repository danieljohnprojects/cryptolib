#pragma once

// Padding is added to a message so that its length in bytes is congruent to 
// PAD_REMAINDER modulo PAD_BLOCK.
#define PAD_BLOCK 64
#define PAD_REMAINDER 56
#define WORDS_PER_BLOCK 16
// ROTATE_LEFT rotates the word x n bits to the left.
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
// Functions and constants for Round 1:
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define FF(a, b, c, d, x, s) { \
    (a) += F ((b), (c), (d)) + (x); \
    (a) = ROTATE_LEFT ((a), (s)); \
  }
#define S11 3
#define S12 7
#define S13 11
#define S14 19
// Functions and constants for Round 2:
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define R2CONST ((uint32_t) 0x5A827999); // Apparently represents sqrt(2)
#define GG(a, b, c, d, x, s) { \
    (a) += G ((b), (c), (d)) + (x) + R2CONST; \
    (a) = ROTATE_LEFT ((a), (s)); \
  }
#define S21 3
#define S22 5
#define S23 9
#define S24 13
// Functions and constants for rounds 3
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define R3CONST ((uint32_t) 0x6ED9EBA1); // Represents sqrt(3)
#define HH(a, b, c, d, x, s) { \
    (a) += H ((b), (c), (d)) + (x) + R3CONST; \
    (a) = ROTATE_LEFT ((a), (s)); \
  }
#define S31 3
#define S32 9
#define S33 11
#define S34 15