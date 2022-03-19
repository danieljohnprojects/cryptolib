#pragma once

#define MD5

#define DIGEST_LENGTH 16

// Padding is added to a message so that its length in bytes is congruent to 
// PAD_REMAINDER modulo PAD_BLOCK.
#define PAD_BLOCK 64
#define PAD_REMAINDER 56
#define WORDS_PER_BLOCK 16
// ROTATE_LEFT rotates the word x n bits to the left.
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

// Functions and constants for Round 1:
#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define FF(a, b, c, d, x, s, t) { \
    (a) += F ((b), (c), (d)) + (x) + (t); \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
}
#define S11 7
#define S12 12
#define S13 17
#define S14 22

// Functions and constants for Round 2:
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define GG(a, b, c, d, x, s, t) { \
    (a) += G ((b), (c), (d)) + (x) + (t); \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
}
#define S21 5
#define S22 9
#define S23 14
#define S24 20

// Functions and constants for rounds 3
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define HH(a, b, c, d, x, s, t) { \
    (a) += H ((b), (c), (d)) + (x) + (t); \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
}
#define S31 4
#define S32 11
#define S33 16
#define S34 23

// Functions and constants for rounds 4
#define I(x, y, z) ((y) ^ ((x) | (~(z))))
#define II(a, b, c, d, x, s, t) { \
    (a) += I ((b), (c), (d)) + (x) + (t); \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
}
#define S41 6
#define S42 10
#define S43 15
#define S44 21
