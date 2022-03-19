#pragma once

#include <stddef.h>
#include <stdint.h>

#include "../src/setup.h"

/**
 * @brief Test that the hash of the given test string starts with the bytes 
 * out1 and out2.
 * 
 * @param hash The hash function to test.
 * @param test_string A null terminated string to hash (the null terminator is 
 * not part of the hash).
 * @param out0 The expected first byte of the hash.
 * @param out1 The expected second byte of the hash.
 */
void test_hash(void (*hash)(const uint8_t *, size_t, uint8_t *), 
               const char *test_string,
               uint8_t out0,
               uint8_t out1);