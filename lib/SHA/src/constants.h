#pragma once

#define DIGEST_LENGTH 20 // Length of the digest in bytes
#define DIGEST_WORD_LENGTH 5

// Padding is added to a message so that its length in bytes is congruent to 
// PAD_REMAINDER modulo PAD_BLOCK.
#define PAD_BLOCK 64
#define PAD_REMAINDER 56
#define WORDS_PER_BLOCK 16

#define F0(B,C,D) (((B) & (C)) | ((~(B)) & D))
#define F1(B,C,D) ((B)^(C)^(D))
#define F2(B,C,D) (((B)&(C)) | ((B)&(D)) | ((C)&(D)))
#define F3(B,C,D) ((B)^(C)^(D))

#define K0 0x5A827999
#define K1 0x6ED9EBA1
#define K2 0x8F1BBCDC
#define K3 0xCA62C1D6

// ROTATE_LEFT rotates the word x n bits to the left.
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
