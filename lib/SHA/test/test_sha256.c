#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shacal_2.h>
#include <SHA256.h>
#include <IO.h>

// #include "../src/SHA1constants.h"

static void init_sha_256_digest(block_t digest) {
    digest[0] = 0x6a09e667;
    digest[1] = 0xbb67ae85;
    digest[2] = 0x3c6ef372;
    digest[3] = 0xa54ff53a;
    digest[4] = 0x510e527f;
    digest[5] = 0x9b05688c;
    digest[6] = 0x1f83d9ab;
    digest[7] = 0x5be0cd19;
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
    init_sha_256_digest(digest_buffer);
    
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

void test_sha256digest()
{
    #ifdef VERBOSE
        printf("=====================\n");
        printf("Testing SHA-256 hash.\n");
        printf("=====================\n");
    #endif

    test_hash(sha256digest, "", 0xe3b0c442, 0x98fc1c14);
    // Should be e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855

    test_hash(sha256digest, "abc", 0xba7816bf, 0x8f01cfea);
    // Should be ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
    
    test_hash(sha256digest, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 0x248d6a61, 0xd20638b8);
    // Should be 248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1

    test_hash(sha256digest, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 0xcf5b16a7, 0x78af8380);
    // Should be cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1
    
    #ifdef LONG_TESTS
    char s[1000000 + 1];
    for (size_t i = 0; i < 1000000; i++)
        s[i] = 'a';
    s[1000000] = '\0';
    test_hash(sha256digest, s, 0x34aa973c, 0xd4c4daa4);
    // Should be 34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f

    // At the moment this test fails.
    // Probably need to put more thought into it to hash a gigabyte long string.
    strcpy(s, "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");
    char long_s[1073741824 + 1];
    for (size_t i = 0; i < 16777216; i++) {
        strncpy(long_s + i*64, s, 64);
    }
    long_s[107371824] = '\0';
    test_hash(sha256digest, s, 0x7789f0c9, 0xef7bfc40);
    // Should be 7789f0c9 ef7bfc40 d9331114 3dfbe69e 2017f592
    #endif
    
    #ifdef VERBOSE
        printf("SHA256 tests passed!!\n\n");
    #endif
}

void test_sha256extend()
{
    #ifdef VERBOSE
        printf("=================================\n");
        printf("Testing SHA256 length extensions.\n");
        printf("=================================\n");
    #endif
    block_t prefix_hash;
    init_sha_256_digest(prefix_hash);

    uint8_t message[] = {'a', 'b', 'c'};
    sha256digest(message, 3, 0, prefix_hash);

    block_t extended_hash;
    for (size_t i = 0; i < WORDS_PER_BLOCK; i++)
        extended_hash[i] = prefix_hash[i];
    
    sha256digest(message, 3, 3, extended_hash);
    
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
    init_sha_256_digest(compare_hash);
    sha256digest(extended_message, 64+3, 0, compare_hash);

    for (size_t i = 0; i < WORDS_PER_BLOCK; i++)
        assert (compare_hash[i] == extended_hash[i]);
    printf("SHA256 length extension tests passed!\n");
}

int main() {
    test_sha256digest();
    test_sha256extend();
}