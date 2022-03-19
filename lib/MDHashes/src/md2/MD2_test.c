#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Hash.h>
#include <IO.h>

#include "MD2.h"

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
               uint8_t out1)
{
    size_t message_length = strlen(test_string);
    uint8_t digest_buffer[DIGEST_LENGTH];
    printf("Computing hash of \"%s\":\n", test_string);
    hash((uint8_t *) test_string, message_length, digest_buffer);
    printf("Hash of \"%s\":\n", test_string);
    print_bytes(digest_buffer, DIGEST_LENGTH);
    printf("\n");
    assert (digest_buffer[0] == out0);
    assert (digest_buffer[1] == out1);
}

void test_MD2digest()
{
    test_hash(md2digest, "", 0x83, 0x50);
    test_hash(md2digest, "a", 0x32, 0xec);
    test_hash(md2digest, "abc", 0xda, 0x85);
    test_hash(md2digest, "message digest", 0xab, 0x4f);
    test_hash(md2digest, "abcdefghijklmnopqrstuvwxyz", 0x4e, 0x8d);
    test_hash(md2digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 0xda, 0x33);
    test_hash(md2digest, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 0xd5, 0x97);
}

int main()
{
    printf("Testing hashes against test vectors...\n");
    test_MD2digest();
    printf("Tests passed!\n\n");
}