#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Hash.h>
#include <IO.h>

#include "../src/md.h"

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
    
    #ifdef VERBOSE
        printf("Computing hash of \"%s\":\n", test_string);
    #endif

    hash((uint8_t *) test_string, message_length, digest_buffer);
    
    #ifdef VERBOSE
        printf("Hash of \"%s\":\n", test_string);
        print_bytes(digest_buffer, DIGEST_LENGTH);
        printf("\n");
    #endif
    
    assert (digest_buffer[0] == out0);
    assert (digest_buffer[1] == out1);
}

void test_MD2digest()
{
    #ifdef VERBOSE
        printf("=================\n");
        printf("Testing MD2 hash.\n");
        printf("=================\n");
    #endif
    test_hash(md2digest, "", 0x83, 0x50);
    test_hash(md2digest, "a", 0x32, 0xec);
    test_hash(md2digest, "abc", 0xda, 0x85);
    test_hash(md2digest, "message digest", 0xab, 0x4f);
    test_hash(md2digest, "abcdefghijklmnopqrstuvwxyz", 0x4e, 0x8d);
    test_hash(md2digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 0xda, 0x33);
    test_hash(md2digest, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 0xd5, 0x97);
}

void test_MD4digest()
{
    #ifdef VERBOSE
        printf("=================\n");
        printf("Testing MD4 hash.\n");
        printf("=================\n");
    #endif
    test_hash(md4digest, "", 0x31, 0xd6);
    test_hash(md4digest, "a", 0xbd, 0xe5);
    test_hash(md4digest, "abc", 0xa4, 0x48);
    test_hash(md4digest, "message digest", 0xd9, 0x13);
    test_hash(md4digest, "abcdefghijklmnopqrstuvwxyz", 0xd7, 0x9e);
    test_hash(md4digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 0x04, 0x3f);
    test_hash(md4digest, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 0xe3, 0x3b);
}

void test_MD5digest()
{
    #ifdef VERBOSE
        printf("=================\n");
        printf("Testing MD5 hash.\n");
        printf("=================\n");
    #endif
    test_hash(md5digest, "", 0xd4, 0x1d);
    test_hash(md5digest, "a", 0x0c, 0xc1);
    test_hash(md5digest, "abc", 0x90, 0x01);
    test_hash(md5digest, "message digest", 0xf9, 0x6b);
    test_hash(md5digest, "abcdefghijklmnopqrstuvwxyz", 0xc3, 0xfc);
    test_hash(md5digest, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 0xd1, 0x74);
    test_hash(md5digest, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 0x57, 0xed);
}

void test_md_hashes()
{
    test_MD4digest();
    test_MD5digest();
    test_MD2digest();
}

int main()
{
    test_md_hashes();
}