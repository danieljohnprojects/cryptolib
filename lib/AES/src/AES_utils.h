/**
 * Functions that are needed at multiple stages throughout the encryption 
 * process.
 */

#pragma once

#include <stdint.h>

uint32_t subword(uint32_t word);
uint32_t rotword(uint32_t word, int n);
void xor_blocks(block_t *b1, block_t *b2, block_t *result);