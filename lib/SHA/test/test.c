#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Hash.h>
#include <IO.h>

#include "../src/constants.h"

static void init_digest(uint8_t digest[DIGEST_LENGTH])
{
    digest[ 0] = 0x67;
    digest[ 1] = 0x45;
    digest[ 2] = 0x23;
    digest[ 3] = 0x01;
    digest[ 4] = 0xef;
    digest[ 5] = 0xcd;
    digest[ 6] = 0xab;
    digest[ 7] = 0x89;
    digest[ 8] = 0x98;
    digest[ 9] = 0xba;
    digest[10] = 0xdc;
    digest[11] = 0xfe;
    digest[12] = 0x10;
    digest[13] = 0x32;
    digest[14] = 0x54;
    digest[15] = 0x76;
    digest[16] = 0xc3;
    digest[17] = 0xd2;
    digest[18] = 0xe1;
    digest[19] = 0xf0;
}

/**
 * @brief Test that the hash of the given test string starts with the correct 
 * bytes.
 * 
 * @param hash The hash function to test.
 * @param test_string A null terminated string to hash (the null terminator is 
 * not part of the hash).
 * @param out0 The expected first byte of the hash.
 * @param out1 The expected second byte of the hash.
 */
void test_hash(void (*hash)(const uint8_t *, size_t, size_t, uint8_t *), 
               const char *test_string,
               uint8_t out0,
               uint8_t out1)
{
    size_t message_length = strlen(test_string);
    uint8_t digest_buffer[DIGEST_LENGTH];
    init_digest(digest_buffer);
    
    #ifdef VERBOSE
        printf("Computing hash of \"%s\":\n", test_string);
    #endif

    // Since we are just doing regular hashes (not length extensions) prefix_length is 0
    hash((uint8_t *) test_string, message_length, 0, digest_buffer);
    
    #ifdef VERBOSE
        printf("\nHash of \"%s\":\n", test_string);
        print_bytes(digest_buffer, DIGEST_LENGTH);
    #endif
    
    assert (digest_buffer[0] == out0);
    assert (digest_buffer[1] == out1);

    #ifdef VERBOSE
        printf("As expected!\n");
        printf("\n");
    #endif
}


void test_sha1digest()
{
    #ifdef VERBOSE
        printf("==================\n");
        printf("Testing SHA1 hash.\n");
        printf("==================\n");
    #endif

    test_hash(sha1digest, "abc", 0xa9, 0x99);

    test_hash(sha1digest, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 0x84, 0x98);

    // char s[1000000 + 1];
    // for (size_t i = 0; i < 1000000; i++)
    //     s[i] = 'a';
    // s[1000000] = '\0';
    // test_hash(sha1digest, s, 0x34, 0xaa);

    char t[640 + 1];
    for (size_t i = 0; i < 20; i++)
        strcpy(t + i*32, "01234567012345670123456701234567");
    test_hash(sha1digest, t, 0xde, 0xa3);
    
    #ifdef VERBOSE
        printf("SHA1 tests passed!!\n\n");
    #endif
}

void test_sha1extend()
{
    #ifdef VERBOSE
        printf("===============================\n");
        printf("Testing SHA1 length extensions.\n");
        printf("===============================\n");
    #endif
    uint8_t prefix_hash[DIGEST_LENGTH];
    init_digest(prefix_hash);

    uint8_t message[] = {'a', 'b', 'c'};
    sha1digest(message, 3, 0, prefix_hash);

    uint8_t extended_hash[DIGEST_LENGTH];
    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        extended_hash[i] = prefix_hash[i];
    
    sha1digest(message, 3, 3, extended_hash);
    
    uint8_t extended_message[64 + 3];
    for (size_t i = 0; i < 64 + 3; i++)
        extended_message[i] = 0;
    extended_message[0] = 'a';
    extended_message[1] = 'b';
    extended_message[2] = 'c';
    extended_message[3] = 0x80;
    extended_message[63] = 0x18;
    extended_message[64] = 'a';
    extended_message[65] = 'b';
    extended_message[66] = 'c';
    uint8_t compare_hash[DIGEST_LENGTH];
    init_digest(compare_hash);
    sha1digest(extended_message, 64+3, 0, compare_hash);

    for (size_t i = 0; i < DIGEST_LENGTH; i++)
        assert (compare_hash[i] == extended_hash[i]);
    printf("SHA1 length extension tests passed!\n");
}

int main()
{
    test_sha1digest();
    test_sha1extend();
}