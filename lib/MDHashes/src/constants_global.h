#pragma once

// Padding is added to a message so that its length in bytes is congruent to 
// PAD_REMAINDER modulo PAD_BLOCK.
#define PAD_BLOCK 64
#define PAD_REMAINDER 56
#define WORDS_PER_BLOCK 16
// ROTATE_LEFT rotates the word x n bits to the left.
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))