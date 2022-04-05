#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Hash.h>
#include <IO.h>

#include "../src/md.h"

void init_md2(uint8_t digest[DIGEST_LENGTH])
{
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        digest[i] = 0;
}

void init_md4(uint8_t digest[DIGEST_LENGTH])
{
    digest[0] = 0x01;
    digest[1] = 0x23;
    digest[2] = 0x45;
    digest[3] = 0x67;
    digest[4] = 0x89;
    digest[5] = 0xab;
    digest[6] = 0xcd;
    digest[7] = 0xef;
    digest[8] = 0xfe;
    digest[9] = 0xdc;
    digest[10] = 0xba;
    digest[11] = 0x98;
    digest[12] = 0x76;
    digest[13] = 0x54;
    digest[14] = 0x32;
    digest[15] = 0x10;
}

void init_md5(uint8_t digest[DIGEST_LENGTH])
{
    digest[0] = 0x01;
    digest[1] = 0x23;
    digest[2] = 0x45;
    digest[3] = 0x67;
    digest[4] = 0x89;
    digest[5] = 0xab;
    digest[6] = 0xcd;
    digest[7] = 0xef;
    digest[8] = 0xfe;
    digest[9] = 0xdc;
    digest[10] = 0xba;
    digest[11] = 0x98;
    digest[12] = 0x76;
    digest[13] = 0x54;
    digest[14] = 0x32;
    digest[15] = 0x10;
}

/**
 * @brief Test that the hash of the given test string starts with the bytes 
 * out1 and out2.
 * 
 * @param hash The hash function to test.
 * @param init The function to initialise the digest buffer.
 * @param test_string A null terminated string to hash (the null terminator is 
 * not part of the hash).
 * @param out0 The expected first byte of the hash.
 * @param out1 The expected second byte of the hash.
 */
void test_hash(void (*hash)(const uint8_t *, size_t, uint8_t *),
               void (*init)(uint8_t *),
               const char *test_string,
               uint8_t out0,
               uint8_t out1)
{
    size_t message_length = strlen(test_string);
    uint8_t digest_buffer[DIGEST_LENGTH];
    // for (size_t i = 0; i < DIGEST_LENGTH; i++)
    //     digest_buffer[i] = 0;
    init(digest_buffer);
    
    #ifdef VERBOSE
        printf("Computing hash of \"%s\":\n", test_string);
    #endif

    hash((uint8_t *) test_string, message_length, digest_buffer);
    
    #ifdef VERBOSE
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
    test_hash(md2digest, init_md2, "", 0x83, 0x50);
    test_hash(md2digest, init_md2, "a", 0x32, 0xec);
    test_hash(md2digest, init_md2, "abc", 0xda, 0x85);
    test_hash(md2digest, init_md2, "message digest", 0xab, 0x4f);
    test_hash(md2digest, init_md2, "abcdefghijklmnopqrstuvwxyz", 0x4e, 0x8d);
    test_hash(md2digest, init_md2, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 0xda, 0x33);
    test_hash(md2digest, init_md2, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 0xd5, 0x97);
    #ifdef VERBOSE
        printf("MD2 tests passed!!\n\n");
    #endif
}


void test_MD4digest()
{
    #ifdef VERBOSE
        printf("=================\n");
        printf("Testing MD4 hash.\n");
        printf("=================\n");
    #endif
    test_hash(md4digest, init_md4, "", 0x31, 0xd6);
    test_hash(md4digest, init_md4, "a", 0xbd, 0xe5);
    test_hash(md4digest, init_md4, "abc", 0xa4, 0x48);
    test_hash(md4digest, init_md4, "message digest", 0xd9, 0x13);
    test_hash(md4digest, init_md4, "abcdefghijklmnopqrstuvwxyz", 0xd7, 0x9e);
    test_hash(md4digest, init_md4, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 0x04, 0x3f);
    test_hash(md4digest, init_md4, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 0xe3, 0x3b);
    #ifdef VERBOSE
        printf("MD4 tests passed!!\n\n");
    #endif
}


void test_MD5digest()
{
    #ifdef VERBOSE
        printf("=================\n");
        printf("Testing MD5 hash.\n");
        printf("=================\n");
    #endif
    test_hash(md5digest, init_md5, "", 0xd4, 0x1d);
    test_hash(md5digest, init_md5, "a", 0x0c, 0xc1);
    test_hash(md5digest, init_md5, "abc", 0x90, 0x01);
    test_hash(md5digest, init_md5, "message digest", 0xf9, 0x6b);
    test_hash(md5digest, init_md5, "abcdefghijklmnopqrstuvwxyz", 0xc3, 0xfc);
    test_hash(md5digest, init_md5, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 0xd1, 0x74);
    test_hash(md5digest, init_md5, "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 0x57, 0xed);
    #ifdef VERBOSE
        printf("MD5 tests passed!!\n\n");
    #endif
}


void test_md_hashes()
{
    test_MD2digest();
    test_MD4digest();
    test_MD5digest();
    #ifdef VERBOSE
        printf("All tests passed!!\n\n");
    #endif
}

int main()
{
    test_md_hashes();
}