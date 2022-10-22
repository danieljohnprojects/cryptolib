#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shacal_1.h>
#include <Hash.h>
#include <IO.h>

// #include "../src/SHA1constants.h"

static void init_sha_1_digest(block_t digest)
{
    digest[0] = 0x67452301;
    digest[1] = 0xefcdab89;
    digest[2] = 0x98badcfe;
    digest[3] = 0x10325476;
    digest[4] = 0xc3d2e1f0;
    // digest[ 0] = 0x67;
    // digest[ 1] = 0x45;
    // digest[ 2] = 0x23;
    // digest[ 3] = 0x01;
    // digest[ 4] = 0xef;
    // digest[ 5] = 0xcd;
    // digest[ 6] = 0xab;
    // digest[ 7] = 0x89;
    // digest[ 8] = 0x98;
    // digest[ 9] = 0xba;
    // digest[10] = 0xdc;
    // digest[11] = 0xfe;
    // digest[12] = 0x10;
    // digest[13] = 0x32;
    // digest[14] = 0x54;
    // digest[15] = 0x76;
    // digest[16] = 0xc3;
    // digest[17] = 0xd2;
    // digest[18] = 0xe1;
    // digest[19] = 0xf0;
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
void
test_hash(
    void (*hash)(const uint8_t *, size_t, size_t, block_t), 
    const char *test_string,
    uint32_t out0,
    uint32_t out1
) {
    size_t message_length = strlen(test_string);
    block_t digest_buffer;
    init_sha_1_digest(digest_buffer);
    
    #ifdef VERBOSE
        printf("Computing hash of \"%s\":\n", test_string);
    #endif

    // Since we are just doing regular hashes (not length extensions) prefix_length is 0
    hash((uint8_t *) test_string, message_length, 0, digest_buffer);
    
    #ifdef VERBOSE
        printf("\nHash of \"%s\":\n", test_string);
        print_words32(digest_buffer, WORDS_PER_BLOCK);
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

    test_hash(sha1digest, "", 0xda39a3ee, 0x5e6b4b0d);
    // Should be da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709

    test_hash(sha1digest, "abc", 0xa9993e36, 0x4706816a);
    // Should be a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
    
    test_hash(sha1digest, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 0x84983e44, 0x1c3bd26e);
    // Should be 84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1

    test_hash(sha1digest, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 0xa49b2446, 0xa02c645b);
    // Should be a49b2446 a02c645b f419f995 b6709125 3a04a259
    
    #ifdef LONG_TESTS
    char s[1000000 + 1];
    for (size_t i = 0; i < 1000000; i++)
        s[i] = 'a';
    s[1000000] = '\0';
    test_hash(sha1digest, s, 0x34aa973c, 0xd4c4daa4);
    // Should be 34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f

    // At the moment this test fails.
    // Probably need to put more thought into it to hash a gigabyte long string.
    strcpy(s, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");
    char long_s[1073741824 + 1];
    for (size_t i = 0; i < 16777216; i++) {
        strncpy(long_s + i*64, s, 64);
    }
    long_s[107371824] = '\0';
    test_hash(sha1digest, s, 0x7789f0c9, 0xef7bfc40);
    // Should be 7789f0c9 ef7bfc40 d9331114 3dfbe69e 2017f592
    #endif
    
    // char t[640 + 1];
    // for (size_t i = 0; i < 20; i++)
    //     strcpy(t + i*32, "01234567012345670123456701234567");
    // test_hash(sha1digest, t, 0xde, 0xa3);
    
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
    block_t prefix_hash;
    init_sha_1_digest(prefix_hash);

    uint8_t message[] = {'a', 'b', 'c'};
    sha1digest(message, 3, 0, prefix_hash);

    block_t extended_hash;
    for (size_t i = 0; i < WORDS_PER_BLOCK; i++)
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

    block_t compare_hash;
    init_sha_1_digest(compare_hash);
    sha1digest(extended_message, 64+3, 0, compare_hash);

    for (size_t i = 0; i < WORDS_PER_BLOCK; i++)
        assert (compare_hash[i] == extended_hash[i]);
    printf("SHA1 length extension tests passed!\n");
}

int main()
{
    test_sha1digest();
    test_sha1extend();
}